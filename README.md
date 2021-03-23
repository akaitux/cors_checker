# CORS Checker

Утилита для проверки CORS. Использует конфигурационный файл, в котором описаны параметры, которым должен соответствовать проверяемый хост. Поддерживает работу с Zabbix - создание Discovery и отправку данных через trapper.

Поддерживается два режима работы:

* cli режим, при котором нужно просто запустить программу без указания флагов или с --debug. Выводит информацию о проведенных проверках в консоль
* zabbix режим, создание discovery и отправка данных в zabbix



## Флаги

**-c --conf** - Путь к конфигу. Если не указан, то будет произведен поиск файла config.yaml рядом с бинарным файлом

**-s --send-to-zabbix** - Провести проверку и отправить данные в zabbix

**-d --zabbix-discovery** - Создать discovery из проверяемых хостов и отправить в zabbix 

**-n --name-filter** - Сделать проверку только для набора конфигураций с указанным именем

**-r --request-to-filter** - Сделать проверку только для указанного хоста

**--debug**


## Как оно работает

1. Исходя из конфигурации определяется, является ли запрос простым или сложным. Простой запрос - запрос, для которого не нужен дополнительный OPTIONS запрос с проверкой доступных заголовков и методов. Проверяется по-стандарту за одним исключением - заголовок Content-Type является признаком сложного запроса независимо от его содержания

2. Производится первая проверка GET запроса, где проверяется заголовок Access-Control-Allow-Origin и Access-Control-Allow-Credentials. Так же учитывется, что при ACAO == "*" не может быть ACAC == "true"

3. Если запрос сложный, производится OPTIONS запрос, где делаются те же проверки, что и в п.2 + проверяется Access-Control-Allow-Headers и Access-Control-Allow-Methods на соответсвие конфигурации.


## Конфигурация

Для отправки данных в zabbix используется кастомный модуль [go-zabbix](https://github.com/hidnoiz/go-zabbix), в котором по-умолчанию настроены основной и резервный zabbix сервера.

Так же в текущей конфигурации по-умолчанию определены параметры:

**zbx_discovery_host** == "virt.cors.checker" - в какой хост отправлять данные

**zbx_discovery_key*** == "disc.cors" - Ключ discovery trapper

**zbx_discovery_item_key** == "cors.check" - Используется при отправки данных, напр. в `cors.check[<url проверяемого хоста>]`

**error_if_unavailable** - Считать ли за ошибку недоступность хоста. По-умолчанию false


Список конфигураций проверок находится в словаре **checks**. Он должен содержать:

**name** - Название проверки, будет использоваться для аггрегирования проверок в zabbix. Обязательное поле

**request_to** - Список запрашиваемых url. Необходимо указывать ссылку с протоколом (http:// или https://). Обязательное поле.

**allowed_hosts** - Адреса, которые будут указаны в заголовке Origin и будут проверяться на наличие в Access-Control-Allow-Origin

Он может содержать:

**credentials** - Требуется ли header Access-Control-Allow-Credentials

**preflight_headers** - Заголовки, которые потребуются от проверяемого хоста в OPTIONS запросе, Access-Control-Allow-Headers 

**preflight_methods** - Методы, которые потребуются от проверяемого хоста в OPTIONS запросе, Access-Control-Allow-Methods

**follow_redirect** - По-умолчанию false

## Нюансы сборки

Требуется перед сборкой сделать `go get --insecure`, т.к. используется кастомный пакет с zabbix модулем.
