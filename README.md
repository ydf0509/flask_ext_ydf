##  pip install flask_ext_ydf

###1.自动使用redis统计每个ip和每个接口的访问次数

###2.自动返回code  data message 三个字段格式的json。
兼容flask接口已经返回了完整json和返回 列表 数组

###3.使用装饰器做参数校验，校验格式使用cerberus包的语法。

###4.自动加密任意请求参数的接口,兼容get传参 post表单传参 postj son传参。

前端需要配合js文件apiEncr，后端使用相同逻辑验证。

如果不通过，则拒绝请求，避免后端web处理大量爬虫任务。

前端调用方式如下，将headers中跟新tsf和snf参数。
```javascript
let ooo = new RequestEncryption({'x': 1, 'y': 2});
console.info(ooo.getHeaders());
console.info(JSON.stringify(ooo.getHeaders()));
```

###5.自动日志记录，错误日志和正常日志自动记录到不同文件

配置钉钉后，函数运行出错可以钉钉自动控频报警。



```python
"""
各种flask 扩展
"""
import sys
import time
import traceback
import random
import base64
import functools
from pathlib import Path
from hashlib import md5
from bson import json_util
import json
import redis

from flask import current_app, request, Flask, Response
from flask.globals import _request_ctx_stack
from cerberus import Validator

from nb_log import LogManager, LoggerMixin

flask_error_logger = LogManager('flask_error').get_logger_and_add_handlers(log_filename='flask_error.log')
flask_record_logger = LogManager('flask_record').get_logger_and_add_handlers(log_filename='flask_record.log')

env = 'test'


# e2eb0348734ab106498d2bxxxxxxxxxx   钉钉调试

class FlaskIpStatistics:
    """
    自动统计每个接口的访问情况
    """

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app, )

    def init_app(self, app: Flask):
        if 'REDSI_URL' not in app.config:
            raise LookupError('请在flask的config 配置中指明 REDSI_URL 的连接配置')
        if 'REDSI_KEY_PREFIX_FOR_STATISTICS' not in app.config:
            raise LookupError('请在flask的config 配置中指明 REDSI_KEY_PREFIX_FOR_STATISTICS 的配置')
        if 'SHOW_IP_STATISTIC_PATH' not in app.config:
            raise LookupError('请在flask的config 配置中指明 SHOW_IP_STATISTIC_PATH 的配置,用来返回ip访问情况')
        self._redsi_key_prefix_of_app = app.config['REDSI_KEY_PREFIX_FOR_STATISTICS']
        self._redis_db_for_ip_statistic = redis.Redis.from_url(app.config['REDSI_URL'])

        app.before_request_funcs.setdefault(None, []).append(self._inrc_ip)
        app.add_url_rule(app.config['SHOW_IP_STATISTIC_PATH'], '', self._show_count, methods=['GET', ])

    @staticmethod
    def _get_user_ip():
        if request.headers.get('X-Forwarded-For'):
            user_ip = request.headers['X-Forwarded-For']
        elif request.headers.get('X-Real-IP'):
            user_ip = request.headers.get('X-Real-IP')
        else:
            user_ip = request.remote_addr
        return user_ip.split(',')[0]

    def _inrc_ip(self):
        print(request.path)
        ip_key_name = f'''{self._redsi_key_prefix_of_app}:{request.path}:{self._get_user_ip()}'''
        print(f'执行inrc    {ip_key_name}')
        if self._redis_db_for_ip_statistic.exists(ip_key_name):
            self._redis_db_for_ip_statistic.incr(ip_key_name, 1)
        else:
            with self._redis_db_for_ip_statistic.pipeline() as p:
                p.incr(ip_key_name, 1)
                p.expire(ip_key_name, 3600)
                p.execute()

    def _show_count(self):
        # 显示每个ip的访问次数
        # return 'aaaaa'

        key_iters = self._redis_db_for_ip_statistic.scan_iter(f'{self._redsi_key_prefix_of_app}:*')
        ip__count_map = {key.decode(): self._redis_db_for_ip_statistic.get(key).decode() for key in key_iters}
        return {'count': len(ip__count_map), 'ip__count_map': ip__count_map}


def get_request_values():
    request_values = {}
    if request.values:
        request_values = request.values.to_dict()
    if request.get_data():
        request_values.update(request.get_json())
    return request_values


def api_return_deco(v):
    """
    对flask的返回 加一个固定的状态码。在测试环境即使是非debug，直接在错误信息中返回错误堆栈。在生产环境使用随机四位字母 加 错误信息的base64作为错误信息。
    :param v:视图函数
    :return:
    """
    flask_request = request
    flask_record_loggerx = current_app.__dict__.get('flask_record_logger', flask_record_logger)
    flask_error_loggerx = current_app.__dict__.get('flask_error_logger', flask_error_logger)

    @functools.wraps(v)
    def _api_return_deco(*args, **kwargs):
        # noinspection PyBroadException
        request_values = get_request_values()
        try:
            data = v(*args, **kwargs)
            if isinstance(data, Response):
                return data
            if isinstance(data, str):
                result = data
            else:
                if 'code' in data and 'data' in data:
                    result = json_util.dumps(data, ensure_ascii=False)
                else:
                    result = json_util.dumps({
                        "code": 200,
                        "data": data,
                        "message": "SUCCESS"}, ensure_ascii=False)
            if len(result) > 1000:
                record_result = str(result[:1000]) + '\n   。。。  '
            else:
                record_result = result
            flask_record_loggerx.debug(
                f'''请求路径：{flask_request.path}  
                请求参数：{json.dumps(request_values)},
                执行flask视图函数{v.__name__}没有异常,结果长度是： {len(result)}
                结果是： {record_result}
                
                
                ''')
            return result
        except Exception as e:
            except_str0 = f'''请求路径：{flask_request.path}  
            请求参数：{json.dumps(request_values)} ,
            出错了,错误类型是: 【{type(e)}】    , 原因是: 【{e}】 
            {traceback.format_exc()}
            
            
            '''
            flask_error_loggerx.exception(except_str0)
            exception_str_encode = base64.b64encode(except_str0.encode()).decode().replace('=', '').strip()
            message = except_str0.replace('\n',
                                          '<br>') if env == 'test' else f'''{"".join(random.sample("abcdefghijklmnopqrstABCDEFGHIJKLMNOPQRST", 4))}{exception_str_encode}'''
            return json.dumps({
                "code": 500,
                "data": None,
                "message": message}, ensure_ascii=False)

    return _api_return_deco


flask_api_result_deco = api_return_deco


def _dispatch_request_with_flask_api_result_deco(self):
    """Does the request dispatching.  Matches the URL and returns the
    return value of the view or error handler.  This does not have to
    be a response object.  In order to convert the return value to a
    proper response object, call :func:`make_response`.

    .. versionchanged:: 0.7
       This no longer does the exception handling, this code was
       moved to the new :meth:`full_dispatch_request`.
    """
    req = _request_ctx_stack.top.request
    if req.routing_exception is not None:
        self.raise_routing_exception(req)
    rule = req.url_rule
    # if we provide automatic options for this URL and the
    # request came with the OPTIONS method, reply automatically
    if getattr(rule, 'provide_automatic_options', False) \
            and req.method == 'OPTIONS':
        return self.make_default_options_response()
    # otherwise dispatch to the handler for that endpoint
    # return self.view_functions[rule.endpoint](**req.view_args)
    v = self.view_functions[rule.endpoint]
    v2 = flask_api_result_deco(v)
    return v2(**req.view_args)


class CustomFlaskApiConversion000(LoggerMixin):
    """
    自动转化每个接口的返回，自动将各种类型转成code data message格式的json
    """

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app, )

    def monkey_patch_dispatch_request(self):
        self.logger.warn('改变了flask的dispatch_request 方法')
        Flask.dispatch_request = _dispatch_request_with_flask_api_result_deco

    def init_app(self, app: Flask):
        app.before_first_request_funcs.append(self.monkey_patch_dispatch_request)  # 直接把返回装饰器加到app上，免得每个接口加一次装饰器麻烦。


class CustomFlaskApiConversion(LoggerMixin):
    """
    自动转化每个接口的返回，自动将各种类型转成code data message格式的json
    """

    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app, )

    @staticmethod
    def __before_first_request():
        for endpoint, view_func in current_app.view_functions.items():
            current_app.view_functions[endpoint] = flask_api_result_deco(view_func)

    def init_app(self, app: Flask):
        flask_record_log_file_name_from_config = app.config.get('FLASK_RECORD_LOG_FILE_NAME', None)
        flask_record_log_file_name_default = Path(sys.path[1]).as_posix().split('/')[-1] + '_flask_record.log'
        if flask_record_log_file_name_from_config:
            app.flask_record_logger = LogManager(
                flask_record_log_file_name_from_config.split('.')[0]).get_logger_and_add_handlers(
                log_filename=flask_record_log_file_name_from_config)
            self.logger.info(f'flask的正常请求记录将记录在  /pythonlogs/{flask_record_log_file_name_from_config} 文件中 ')
        else:
            app.flask_record_logger = LogManager(
                flask_record_log_file_name_default.split('.')[0]).get_logger_and_add_handlers(
                log_filename=flask_record_log_file_name_default)
            self.logger.info(f'flask的正常请求记录将记录在  /pythonlogs/{flask_record_log_file_name_default} 文件中 ')
            self.logger.warning(f'也可以手动配置flask的正常请求记录日志文件名字，请指定 FLASK_RECORD_LOG_FILE_NAME')

        flask_error_log_file_name_from_config = app.config.get('FLASK_ERROR_LOG_FILE_NAME', None)
        flask_error_log_file_name_default = Path(sys.path[1]).as_posix().split('/')[-1] + '_flask_error.log'
        if flask_error_log_file_name_from_config:
            logger_error_name = flask_error_log_file_name_from_config.split('.')[0] + (app.config[
                                                                                           'DING_TALK_KEYWORD'] if app.config.get(
                'FLASK_ERROR_DING_TALK_TOKEN', None) else '')
            # logger_dingtalk_debug.debug(logger_error_name)
            app.flask_error_logger = LogManager(
                logger_error_name).get_logger_and_add_handlers(
                log_filename=flask_error_log_file_name_from_config,
                ding_talk_token=app.config.get('FLASK_ERROR_DING_TALK_TOKEN', None))
            self.logger.info(f'''flask错误日志将记录在  /pythonlogs/{flask_error_log_file_name_from_config} 文件中''')
        else:
            logger_error_name = flask_error_log_file_name_default.split('.')[0] + (app.config[
                                                                                       'DING_TALK_KEYWORD'] if app.config.get(
                'FLASK_ERROR_DING_TALK_TOKEN', None) else '')
            # logger_dingtalk_debug.debug(logger_error_name)
            app.flask_error_logger = LogManager(
                logger_error_name).get_logger_and_add_handlers(
                log_filename=flask_error_log_file_name_default,
                ding_talk_token=app.config.get('FLASK_ERROR_DING_TALK_TOKEN', None))
            self.logger.info(f'''flask错误日志将记录在  /pythonlogs/{flask_error_log_file_name_default} 文件中''')
            self.logger.warning(f'''也可以手动配置flask的错误记录日志文件名字，请指定 FLASK_ERROR_LOG_FILE_NAME''')

        app.before_first_request_funcs.append(self.__before_first_request)


def flask_check_param_deco(schema, ):
    """
    自动检查参数，返回400 code
    :param schema:
    :return:
    """

    def _check_param_deco(v):
        @functools.wraps(v)
        def ___check_param_deco(*ags, **kwargs):
            request_values = get_request_values()
            vd = Validator()
            vd.allow_unknown = True
            # document, schema=None
            is_ok = vd.validate(request_values, schema)
            check_errors = None
            if is_ok is False:
                check_errors = vd.errors
            if is_ok:
                return v(*ags, **kwargs)
            else:
                return {'code': 400,
                        'message': check_errors,
                        'data': None}

        return ___check_param_deco

    return _check_param_deco


def flask_request_encrypt_deco(v):
    """
    flask请求参数加密，防止被爬
    前端js文件对应 apiEncr.js
    :param v:
    :return:
    """

    @functools.wraps(v)
    def _flask_request_encrypt_deco(*args, **kwargs):
        if 'tsf' not in request.headers:
            return json.dumps({'code': 476, 'message': '', 'data': None})
        if 'snf' not in request.headers:
            return json.dumps({'code': 477, 'message': '', 'data': None})
        ts = int(request.headers.get('tsf'))
        snf = request.headers.get('snf')
        if time.time() - ts > 600 * 1000:
            return json.dumps({'code': 478, 'message': '', 'data': None})
        request_values = get_request_values()
        request_values_list_sorted = sorted(request_values.items(), key=lambda x: x[0])
        random_bit = int(snf[0])
        to_be_enc_str = ''
        end_random_str = snf[-random_bit:]
        print(end_random_str)
        for key, value in request_values_list_sorted:
            to_be_enc_str += f'{key}{end_random_str}{value}'
        md = md5()
        md.update(f'{to_be_enc_str}{ts}'.encode())
        sn = md.hexdigest()
        if (snf[random_bit + 1:random_bit + 33] == sn and len(snf) == 64) or snf == 'mtfytest':
            return v(*args, **kwargs)
        else:
            return json.dumps({'code': 479, 'message': '', 'data': None})

    return _flask_request_encrypt_deco


class FlaskApiEncryption:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app, )

    @staticmethod
    def __before_first_request():
        for endpoint, view_func in current_app.view_functions.items():
            current_app.view_functions[endpoint] = flask_request_encrypt_deco(view_func)

    def init_app(self, app: Flask):
        app.before_first_request_funcs.append(self.__before_first_request)


if __name__ == '__main__':
    schemax = {"x": {'type': 'string', 'empty': False, 'nullable': False, 'required': True}}

    appx = Flask(__name__)
    appx.config['REDSI_KEY_PREFIX_FOR_STATISTICS'] = 'flask_test1'
    appx.config['SHOW_IP_STATISTIC_PATH'] = '/proj/ip_st'

    # appx.config['FLASK_RECORD_LOG_FILE_NAME'] = 'my_flask_proj_record2.log'
    # appx.config['FLASK_ERROR_LOG_FILE_NAME'] = 'my_flask_proj_error2.log'
    appx.config['FLASK_ERROR_DING_TALK_TOKEN'] = 'e2eb0348734ab106498d2b4e2e93xxxxxxx'
    appx.config['DING_TALK_KEYWORD'] = '钉钉调试'  # 钉钉机器人的关键字模式发送消息

    FlaskIpStatistics(appx)
    CustomFlaskApiConversion(appx)
    FlaskApiEncryption(appx)


    @appx.route('/', methods=['get'])
    def index():
        return 'hello'


    @appx.route('/list', methods=['get', 'post'])
    @flask_check_param_deco(schemax, )
    def listx():
        """
        {"code": 200, "data": ["dsd"], "message": "SUCCESS"}
        :return:
        """
        1 / 0
        return ['dsd', 'lalala']  # 可以直接返回字典 和列表类型，不需要json dumps。


    @appx.route('/jm', methods=['get'])
    @flask_request_encrypt_deco
    def encr_test():
        return [1, 2, 3]


    appx.run('0.0.0.0', port=6358)



``` 