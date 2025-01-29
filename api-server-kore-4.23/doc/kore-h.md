Этот код — это заголовочный файл из проекта **Kore**, содержащий определения макросов, структур и типов, используемых в сервере. Разберём его по частям.

---

### 1. **Определения для C и C++**
```c
#if defined(__cplusplus)
extern "C" {
#endif
```
Если код компилируется в **C++**, то `extern "C"` предотвращает изменение имен функций компилятором (name mangling), позволяя вызывать их из C.

---

### 2. **Проверки для macOS**
```c
#if defined(__APPLE__)
#undef daemon
extern int daemon(int, int);
#define st_mtim		st_mtimespec
#endif
```
- В macOS (`__APPLE__`) удаляется (`#undef`) стандартное определение `daemon` и переопределяется.
- Поле `st_mtim` структуры `stat` заменяется на `st_mtimespec` (так используется в macOS).

---

### 3. **Определение поддержки `sendfile`**
```c
#if !defined(KORE_NO_SENDFILE)
#if defined(__MACH__) || defined(__FreeBSD_version) || defined(__linux__)
#define KORE_USE_PLATFORM_SENDFILE	1
#endif
#endif
```
Если **не** отключена поддержка `sendfile` (`KORE_NO_SENDFILE` не определён), то на macOS, FreeBSD и Linux включается флаг `KORE_USE_PLATFORM_SENDFILE`, означающий, что сервер сможет отправлять файлы через `sendfile()`.

---

### 4. **Поддержка pledge в OpenBSD**
```c
#if defined(__OpenBSD__)
#define KORE_USE_PLATFORM_PLEDGE	1
#endif
```
Если система OpenBSD, включается `pledge()` — механизм ограничения системных вызовов для безопасности.

---

### 5. **Определения для OpenSSL**
```c
#if defined(TLS_BACKEND_OPENSSL)
#include <openssl/x509.h>
#include <openssl/ssl.h>
typedef X509		KORE_X509;
typedef SSL		KORE_TLS;
typedef SSL_CTX		KORE_TLS_CTX;
typedef X509_NAME	KORE_X509_NAMES;
typedef EVP_PKEY	KORE_PRIVATE_KEY;
#else
typedef void		KORE_X509;
typedef void		KORE_TLS;
typedef void		KORE_TLS_CTX;
typedef void		KORE_X509_NAMES;
typedef void		KORE_PRIVATE_KEY;
#endif
```
Если сервер скомпилирован с OpenSSL (`TLS_BACKEND_OPENSSL`), вводятся алиасы типов для удобства:
- `KORE_X509` → `X509` (сертификат)
- `KORE_TLS` → `SSL` (TLS-сессия)
- `KORE_TLS_CTX` → `SSL_CTX` (контекст SSL)

Если OpenSSL **не используется**, вместо типов подставляются `void` (чтобы код компилировался без OpenSSL).

---

### 6. **Определения параметров TLS**
```c
#define KORE_RSAKEY_BITS	4096
```
Используемая длина RSA-ключа — **4096 бит**.

```c
#define KORE_TLS_VERSION_1_3	0
#define KORE_TLS_VERSION_1_2	1
#define KORE_TLS_VERSION_BOTH	2
```
Определяются поддерживаемые версии TLS.

---

### 7. **Определения кодов завершения**
```c
#define KORE_QUIT_NONE		-1
#define KORE_QUIT_NORMAL	0
#define KORE_QUIT_FATAL		1
```
- `KORE_QUIT_NONE` (-1) — не запрашивался выход
- `KORE_QUIT_NORMAL` (0) — сервер завершился нормально
- `KORE_QUIT_FATAL` (1) — критическая ошибка

---

### 8. **Базовые макросы**
```c
#define KORE_RESULT_ERROR	0
#define KORE_RESULT_OK		1
#define KORE_RESULT_RETRY	2
```
Коды возврата для функций:
- Ошибка
- Успешно
- Повторить операцию

```c
#define KORE_WAIT_INFINITE	(u_int64_t)-1
#define KORE_RESEED_TIME	(1800 * 1000)
```
- `KORE_WAIT_INFINITE` означает бесконечное ожидание.
- `KORE_RESEED_TIME` — время для перегенерации случайных чисел (**1800 секунд** = 30 минут).

---

### 9. **Макросы для ошибок**
```c
#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)
```
Эти макросы возвращают строковые представления ошибок для обычных (`errno_s`) и SSL-ошибок (`ssl_errno_s`).

---

### 10. **Файлы и пути**
```c
#define KORE_PIDFILE_DEFAULT		"kore.pid"
#define KORE_DHPARAM_PATH		PREFIX "/share/kore/ffdhe4096.pem"
```
- `KORE_PIDFILE_DEFAULT` — путь к PID-файлу.
- `KORE_DHPARAM_PATH` — путь к параметрам Diffie-Hellman.

---

### 11. **Структуры данных**
#### **`kore_fileref`** — файловые ссылки
```c
struct kore_fileref {
	int				cnt;
	int				flags;
	int				ontls;
	off_t				size;
	char				*path;
	u_int64_t			mtime;
	time_t				mtime_sec;
	u_int64_t			expiration;
	void				*base;
	int				fd;
	TAILQ_ENTRY(kore_fileref)	list;
};
```
Используется для работы с файлами:
- `cnt` — счётчик ссылок
- `size` — размер файла
- `mtime` — время модификации
- `fd` — файловый дескриптор

#### **`netbuf`** — сетевой буфер
```c
struct netbuf {
	u_int8_t		*buf;
	size_t			s_off;
	size_t			b_len;
	size_t			m_len;
	u_int8_t		type;
	u_int8_t		flags;
	struct kore_fileref	*file_ref;
	off_t			fd_off;
	off_t			fd_len;
	struct connection	*owner;
	void			*extra;
	int			(*cb)(struct netbuf *);
	TAILQ_ENTRY(netbuf)	list;
};
```
Используется для сетевых соединений:
- `buf` — данные
- `b_len` — длина данных
- `flags` — флаги
- `owner` — ссылка на соединение
- `cb` — callback-функция обработки

---

### 12. **Классификация соединений**
```c
#define KORE_TYPE_LISTENER	1
#define KORE_TYPE_CONNECTION	2
#define KORE_TYPE_PGSQL_CONN	3
#define KORE_TYPE_TASK		4
#define KORE_TYPE_PYSOCKET	5
#define KORE_TYPE_CURL_HANDLE	6
```
Определяет тип объекта:
- `KORE_TYPE_LISTENER` — слушающий сокет
- `KORE_TYPE_CONNECTION` — соединение
- `KORE_TYPE_PGSQL_CONN` — подключение к PostgreSQL

---

### 13. **Коды событий**
```c
#define KORE_EVENT_READ		0x01
#define KORE_EVENT_WRITE	0x02
#define KORE_EVENT_ERROR	0x04
```
Флаги событий:
- `READ` (чтение)
- `WRITE` (запись)
- `ERROR` (ошибка)

---

### 14. **WebSocket**
```c
#define WEBSOCKET_OP_TEXT	0x01
#define WEBSOCKET_OP_BINARY	0x02
#define WEBSOCKET_OP_CLOSE	0x08
#define WEBSOCKET_OP_PING	0x09
#define WEBSOCKET_OP_PONG	0x0a
```
Определяет тип WebSocket-фреймов.

---

### Итог
Этот код — заголовочный файл, определяющий:
1. Платформно-зависимые особенности (macOS, Linux, OpenBSD).
2. Поддержку TLS и OpenSSL.
3. Основные структуры (буферы, файлы, соединения).
4. Макросы для кодов завершения, обработки ошибок.
5. Определения для WebSocket и работы с файлами.

Это часть ядра **Kore**, которая описывает основные механизмы работы сервера.


### 1. **Обработка событий (`struct kore_event`)**
   ```c
   struct kore_event {
       int type;
       int flags;
       void (*handle)(void *, int);
   } __attribute__((packed));
   ```
- `type` – тип события (например, чтение, запись, ошибка).
- `flags` – дополнительные параметры события.
- `handle` – указатель на функцию-обработчик.

### 2. **Соединение (`struct connection`)**
   ```c
   struct connection {
       struct kore_event evt;
       int fd;
       u_int8_t state;
       u_int8_t proto;
       struct listener *owner;
       KORE_TLS *tls;
       KORE_X509 *tls_cert;
       char *tls_sni;
       int tls_reneg;
       u_int16_t flags;
       void *hdlr_extra;
       int (*handle)(struct connection *);
       void (*disconnect)(struct connection *);
       int (*read)(struct connection *, size_t *);
       int (*write)(struct connection *, size_t, size_t *);
       int family;
   ```
- Управляет TCP-соединением.
- `fd` – файловый дескриптор сокета.
- `state` – состояние соединения (например, TLS handshake, установлено, разрыв).
- `proto` – протокол (HTTP, WebSocket и т. д.).
- `tls` – структура для работы с TLS.
- `read/write` – указатели на функции обработки ввода-вывода.
- `owner` – указатель на `listener`, который принял соединение.

### 3. **Маршрутизация HTTP (`struct kore_route`)**
   ```c
   struct kore_route {
       char *path;
       char *func;
       int type;
       int methods;
       regex_t rctx;
       struct kore_domain *dom;
       struct kore_auth *auth;
       struct kore_runtime_call *rcall;
   };
   ```
- `path` – маршрут (например, `/api/data`).
- `func` – имя обработчика.
- `methods` – HTTP-методы (GET, POST).
- `dom` – домен, к которому относится маршрут.
- `auth` – механизм аутентификации.

### 4. **Домены (`struct kore_domain`)**
   ```c
   struct kore_domain {
       char *domain;
       struct kore_server *server;
       char *cafile;
       char *certfile;
       char *certkey;
       KORE_TLS_CTX *tls_ctx;
   };
   ```
- Описывает домен (например, `example.com`).
- `certfile`, `certkey` – файлы TLS-сертификатов.
- `tls_ctx` – контекст TLS-соединений.

### 5. **Прослушиватель (`struct listener`)**
   ```c
   struct listener {
       struct kore_event evt;
       int fd;
       int family;
       char *port;
       char *host;
       struct kore_server *server;
   };
   ```
- `fd` – сокет, на котором слушаются входящие соединения.
- `port` – порт (например, `443`).
- `host` – IP-адрес.

---

В целом, это основной код инфраструктуры Kore, обеспечивающий сетевые соединения, TLS, обработку маршрутов и событий.


---

### **1. Сервер (`struct kore_server`)**
```c
struct kore_server {
    int tls;
    char *name;
    struct kore_domain_h domains;
    LIST_HEAD(, listener) listeners;
    LIST_ENTRY(kore_server) list;
};
```
- **`tls`** – включён ли TLS.
- **`name`** – имя сервера.
- **`domains`** – список доменов (`struct kore_domain_h`).
- **`listeners`** – список прослушивающих сокетов (`struct listener`).

---

### **2. Аутентификация (`struct kore_auth`)**
```c
struct kore_auth {
    u_int8_t type;
    char *name;
    char *value;
    char *redirect;
    struct kore_validator *validator;
    TAILQ_ENTRY(kore_auth) list;
};
```
- **`type`** – способ аутентификации:
    - `KORE_AUTH_TYPE_COOKIE` (1) – через куки.
    - `KORE_AUTH_TYPE_HEADER` (2) – через HTTP-заголовок.
    - `KORE_AUTH_TYPE_REQUEST` (3) – через параметры запроса.
- **`name`** – имя параметра.
- **`value`** – ожидаемое значение.
- **`redirect`** – куда перенаправлять в случае неудачи.
- **`validator`** – проверяющая функция.

---

### **3. Модули (`struct kore_module`)**
```c
struct kore_module {
    void *handle;
    char *path;
    char *onload;
    int type;
    struct kore_runtime_call *ocb;
    struct kore_module_functions *fun;
    struct kore_runtime *runtime;
    TAILQ_ENTRY(kore_module) list;
};
```
- **Загружаемые модули**, например, в `.so` файлах.
- **`onload`** – функция, вызываемая при загрузке.
- **`fun`** – набор функций для управления модулем.

---

### **4. Воркеры (`struct kore_worker`)**
```c
struct kore_worker {
    u_int16_t id;
    u_int16_t cpu;
    int ready;
    int running;
    pid_t pid;
    int pipe[2];
    struct connection *msg[2];
    u_int8_t has_lock;
    int restarted;
    u_int64_t time_locked;
    struct kore_route *active_route;
    struct kore_privsep *ps;
};
```
- **Работают в отдельных процессах**.
- **Обмениваются данными с родительским процессом через `pipe`**.
- **`active_route`** – текущий обрабатываемый маршрут.

---

### **5. Валидация (`struct kore_validator`)**
```c
struct kore_validator {
    u_int8_t type;
    char *name;
    char *arg;
    regex_t rctx;
    struct kore_runtime_call *rcall;
};
```
- **`type`** – метод валидации:
    - `KORE_VALIDATOR_TYPE_REGEX` (1) – через регулярное выражение.
    - `KORE_VALIDATOR_TYPE_FUNCTION` (2) – через функцию.

---

### **6. Буфер (`struct kore_buf`)**
```c
struct kore_buf {
    u_int8_t *data;
    int flags;
    size_t length;
    size_t offset;
};
```
- Используется для хранения данных (например, логов).

---

### **Вывод**
- **Структуры отвечают за управление сервером, обработку HTTP, аутентификацию и работу воркеров.**
- **Kore модульный, поддерживает динамическую загрузку расширений.**
- **Есть защита через валидацию запросов.**
- **Воркеры работают как отдельные процессы для масштабируемости.**

Этот фрагмент кода отвечает за работу с JSON, управление памятью и таймерами в Kore.

---

### **1. Работа с JSON**
#### **Типы данных JSON**
```c
#define KORE_JSON_TYPE_OBJECT     0x0001
#define KORE_JSON_TYPE_ARRAY      0x0002
#define KORE_JSON_TYPE_STRING     0x0004
#define KORE_JSON_TYPE_NUMBER     0x0008
#define KORE_JSON_TYPE_LITERAL    0x0010
#define KORE_JSON_TYPE_INTEGER    0x0020
#define KORE_JSON_TYPE_INTEGER_U64 0x0040
```
JSON поддерживает:
- **Объекты (`OBJECT`)** и **массивы (`ARRAY`)**.
- **Строки (`STRING`)**, **числа (`NUMBER`)**, **литералы (`LITERAL`)**.
- **Целые числа (`INTEGER`, `INTEGER_U64`)**.

#### **Коды ошибок**
```c
#define KORE_JSON_ERR_NONE           0
#define KORE_JSON_ERR_INVALID_OBJECT 1
#define KORE_JSON_ERR_INVALID_ARRAY  2
#define KORE_JSON_ERR_INVALID_STRING 3
#define KORE_JSON_ERR_INVALID_NUMBER 4
#define KORE_JSON_ERR_INVALID_LITERAL 5
#define KORE_JSON_ERR_DEPTH          6
#define KORE_JSON_ERR_EOF            7
#define KORE_JSON_ERR_INVALID_JSON   8
#define KORE_JSON_ERR_NOT_FOUND      10
#define KORE_JSON_ERR_TYPE_MISMATCH  11
```
Ошибки связаны с некорректной структурой JSON, переполнением глубины (`DEPTH`), несоответствием типов.

#### **Поиск элементов JSON**
Макросы упрощают вызов `kore_json_find()`:
```c
#define kore_json_find_object(j, p)    kore_json_find(j, p, KORE_JSON_TYPE_OBJECT)
#define kore_json_find_array(j, p)     kore_json_find(j, p, KORE_JSON_TYPE_ARRAY)
#define kore_json_find_string(j, p)    kore_json_find(j, p, KORE_JSON_TYPE_STRING)
#define kore_json_find_number(j, p)    kore_json_find(j, p, KORE_JSON_TYPE_NUMBER)
```
Позволяют искать в JSON объекте нужный элемент.

#### **Создание элементов JSON**
```c
#define kore_json_create_object(o, n)   kore_json_create_item(o, n, KORE_JSON_TYPE_OBJECT)
#define kore_json_create_string(o, n, v) kore_json_create_item(o, n, KORE_JSON_TYPE_STRING, v)
```
Эти макросы вызывают `kore_json_create_item()`, который создаёт новый JSON-объект.

#### **Структура JSON**
```c
struct kore_json {
    const u_int8_t *data;
    int depth;
    size_t length;
    size_t offset;
    struct kore_buf tmpbuf;
    struct kore_json_item *root;
};
```
- **`data`** – сырые JSON-данные.
- **`depth`** – текущая глубина парсинга.
- **`root`** – корневой элемент JSON.

```c
struct kore_json_item {
    u_int32_t type;
    char *name;
    struct kore_json_item *parent;
    union {
        TAILQ_HEAD(, kore_json_item) items;
        char *string;
        double number;
        int literal;
        int64_t integer;
        u_int64_t u64;
    } data;
};
```
- **`type`** – тип элемента (объект, массив, строка и т. д.).
- **`data`** – хранит значение элемента (строка, число и т. д.).
- **`items`** – вложенные JSON-объекты.

---

### **2. Управление памятью (Пулы объектов)**
```c
struct kore_pool_region {
    void *start;
    size_t length;
    LIST_ENTRY(kore_pool_region) list;
};
```
Хранит область памяти, выделенную пулу.

```c
struct kore_pool_entry {
    u_int8_t state;
    struct kore_pool_region *region;
    LIST_ENTRY(kore_pool_entry) list;
};
```
Запись о выделенной памяти в пуле.

```c
struct kore_pool {
    size_t elen;       /* Размер элемента */
    size_t slen;       /* Размер блока памяти */
    size_t elms;       /* Количество элементов */
    size_t inuse;      /* Используемые элементы */
    size_t growth;     /* Шаг роста */
    volatile int lock; /* Блокировка для многопоточного доступа */
    char *name;
    
    LIST_HEAD(, kore_pool_region) regions;
    LIST_HEAD(, kore_pool_entry) freelist;
};
```
- **Используется для эффективного выделения памяти под объекты.**
- **Позволяет повторно использовать выделенную память.**

---

### **3. Таймеры**
```c
struct kore_timer {
    u_int64_t nextrun;
    u_int64_t interval;
    int flags;
    void *arg;
    void (*cb)(void *, u_int64_t);
    TAILQ_ENTRY(kore_timer) list;
};
```
- **Таймеры вызывают функции через заданный интервал**.
- **`nextrun`** – время следующего срабатывания.
- **`interval`** – период выполнения.
- **`cb`** – указатель на вызываемую функцию.

---

### **Вывод**
- **Поддержка JSON встроена в Kore, включая парсинг и создание объектов.**
- **Для работы с памятью Kore использует пулы, что повышает скорость работы.**
- **Система таймеров позволяет выполнять задачи по расписанию.**


Этот код отвечает за управление процессами и межпроцессное взаимодействие (IPC) в Kore.

---

### **1. Определение процессов в Kore**
Kore использует несколько типов процессов:

```c
#define KORE_WORKER_KEYMGR_IDX  0
#define KORE_WORKER_ACME_IDX    1
#define KORE_WORKER_BASE        2
#define KORE_WORKER_KEYMGR      2000
#define KORE_WORKER_ACME        2001
#define KORE_WORKER_MAX         UCHAR_MAX
```
- **`KEYMGR (2000)`** – процесс управления ключами.
- **`ACME (2001)`** – процесс автоматического обновления сертификатов.
- **`BASE (2)`** – основные рабочие процессы.

Максимальное количество воркеров – `UCHAR_MAX` (255).

---

### **2. Политика работы воркеров**
```c
#define KORE_WORKER_POLICY_RESTART   1
#define KORE_WORKER_POLICY_TERMINATE 2
```
- **`RESTART`** – воркер перезапускается после завершения.
- **`TERMINATE`** – воркер завершается без перезапуска.

---

### **3. Межпроцессные сообщения (IPC)**
```c
#define KORE_MSG_WEBSOCKET        1
#define KORE_MSG_KEYMGR_REQ       2
#define KORE_MSG_KEYMGR_RESP      3
#define KORE_MSG_SHUTDOWN         4
#define KORE_MSG_ENTROPY_REQ      5
#define KORE_MSG_ENTROPY_RESP     6
#define KORE_MSG_CERTIFICATE      7
#define KORE_MSG_CERTIFICATE_REQ  8
#define KORE_MSG_CRL              9
#define KORE_MSG_ACCEPT_AVAILABLE 10
#define KORE_PYTHON_SEND_OBJ      11
#define KORE_MSG_WORKER_LOG       12
#define KORE_MSG_FATALX           13
#define KORE_MSG_ACME_BASE        100
#define KORE_MSG_APP_BASE         200
```
Эти сообщения используются для взаимодействия между процессами.  
Примеры:
- **`KORE_MSG_WEBSOCKET (1)`** – передача WebSocket-сообщений.
- **`KORE_MSG_KEYMGR_REQ (2)`** и **`KORE_MSG_KEYMGR_RESP (3)`** – запросы к процессу управления ключами.
- **`KORE_MSG_SHUTDOWN (4)`** – команда завершения работы.
- **`KORE_MSG_CERTIFICATE_REQ (8)`** – запрос на сертификат.
- **`KORE_MSG_WORKER_LOG (12)`** – запись логов от воркеров.

Для сообщений от пользовательских приложений зарезервирован диапазон **от 201 и выше**.

---

### **4. Определённые получатели сообщений**
```c
#define KORE_MSG_PARENT     1000
#define KORE_MSG_WORKER_ALL 1001
```
- **`KORE_MSG_PARENT (1000)`** – сообщение отправляется главному процессу.
- **`KORE_MSG_WORKER_ALL (1001)`** – сообщение отправляется всем воркерам.

---

### **5. Структуры сообщений**
```c
struct kore_msg {
    u_int8_t  id;       // ID сообщения
    u_int16_t src;      // Отправитель
    u_int16_t dst;      // Получатель
    size_t    length;   // Размер данных
};
```
Используется для передачи сообщений между процессами.

```c
struct kore_keyreq {
    int      padding;
    char     domain[KORE_DOMAINNAME_LEN + 1];
    size_t   data_len;
    u_int8_t data[];
};
```
Эта структура описывает запросы на управление ключами (например, генерация SSL-сертификатов).

```c
struct kore_x509_msg {
    char     domain[KORE_DOMAINNAME_LEN + 1];
    size_t   data_len;
    u_int8_t data[];
};
```
Используется для работы с X.509-сертификатами.

---

### **6. Важные глобальные переменные**
```c
extern pid_t kore_pid;       // PID главного процесса
extern int   kore_quit;      // Флаг завершения работы
extern int   kore_quiet;     // Флаг тихого режима (без вывода в консоль)
extern int   skip_chroot;    // Флаг пропуска chroot
extern int   skip_runas;     // Флаг пропуска смены пользователя
extern int   kore_foreground;// Флаг работы в foreground-режиме
extern char  *kore_pidfile;  // Файл с PID процесса
```
Определяют параметры работы Kore.

```c
extern volatile sig_atomic_t sig_recv; // Сигналы, полученные процессом
```
Используется для обработки сигналов (`SIGINT`, `SIGTERM`).

```c
extern int kore_keymgr_active; // Флаг активности процесса KEYMGR
```
Показывает, работает ли менеджер ключей.

---

### **7. Параметры сервера**
```c
extern u_int8_t  nlisteners;                // Количество слушающих сокетов
extern u_int16_t cpu_count;                 // Количество CPU
extern u_int8_t  worker_count;              // Количество воркеров
extern u_int32_t worker_rlimit_nofiles;     // Максимальное количество файловых дескрипторов
extern u_int32_t worker_max_connections;    // Максимальное число соединений
extern u_int32_t worker_active_connections; // Текущее число соединений
extern u_int32_t worker_accept_threshold;   // Лимит принятых соединений на воркер
extern u_int64_t kore_websocket_maxframe;   // Максимальный размер WebSocket-фрейма
extern u_int64_t kore_websocket_timeout;    // Тайм-аут WebSocket-соединения
extern u_int32_t kore_socket_backlog;       // Очередь входящих соединений
```
Эти переменные определяют ресурсы и настройки сервера.

---

### **8. Структуры воркеров и доменов**
```c
extern struct kore_worker *worker;      // Указатель на текущего воркера
extern struct kore_pool    nb_pool;     // Пул памяти
extern struct kore_domain *primary_dom; // Основной домен
extern struct kore_server_list kore_servers; // Список серверов
```
Используются для управления процессами, памятью и серверами.

---

### **Вывод**
1. **В Kore есть несколько типов процессов (ключевой менеджер, ACME, воркеры).**
2. **IPC (межпроцессное взаимодействие) реализовано через `struct kore_msg` и кодированные сообщения.**
3. **Работа сервера управляется глобальными переменными (`worker_count`, `worker_max_connections`, `kore_websocket_timeout`).**
4. **Есть встроенная поддержка управления ключами (`kore_keyreq`) и SSL-сертификатами (`kore_x509_msg`).**

Ты прислал два больших фрагмента кода из Kore, которые связаны с **работой JSON**, **процессами (воркерами)** и **межпроцессным взаимодействием (IPC)**. Давай разберём их подробно.

---

# **1. Работа с JSON в Kore**
(Разбор первой части кода)

## **1.1. Типы данных JSON**
В Kore JSON представлен разными типами, которые кодируются битовыми флагами:

```c
#define KORE_JSON_TYPE_OBJECT      0x0001  // JSON-объект { ... }
#define KORE_JSON_TYPE_ARRAY       0x0002  // JSON-массив [ ... ]
#define KORE_JSON_TYPE_STRING      0x0004  // Строка "..."
#define KORE_JSON_TYPE_NUMBER      0x0008  // Число (целое или с плавающей точкой)
#define KORE_JSON_TYPE_LITERAL     0x0010  // Логические значения (true, false, null)
#define KORE_JSON_TYPE_INTEGER     0x0020  // Целочисленное значение (int64_t)
#define KORE_JSON_TYPE_INTEGER_U64 0x0040  // Беззнаковое целочисленное значение (uint64_t)
```
Эти флаги используются при парсинге и создании JSON-объектов.

Также определены **константы для литералов**:
```c
#define KORE_JSON_FALSE  0  // Логическое false
#define KORE_JSON_TRUE   1  // Логическое true
#define KORE_JSON_NULL   2  // null
```

Максимальная глубина вложенности JSON (чтобы не было рекурсивных атак):
```c
#define KORE_JSON_DEPTH_MAX  10
```

## **1.2. Ошибки при обработке JSON**
```c
#define KORE_JSON_ERR_NONE             0  // Нет ошибки
#define KORE_JSON_ERR_INVALID_OBJECT    1  // Ошибка в объекте
#define KORE_JSON_ERR_INVALID_ARRAY     2  // Ошибка в массиве
#define KORE_JSON_ERR_INVALID_STRING    3  // Ошибка в строке
#define KORE_JSON_ERR_INVALID_NUMBER    4  // Ошибка в числе
#define KORE_JSON_ERR_INVALID_LITERAL   5  // Ошибка в литерале (true, false, null)
#define KORE_JSON_ERR_DEPTH             6  // Превышена максимальная глубина
#define KORE_JSON_ERR_EOF               7  // Неожиданный конец файла
#define KORE_JSON_ERR_INVALID_JSON      8  // JSON повреждён
#define KORE_JSON_ERR_INVALID_SEARCH    9  // Ошибка при поиске элемента
#define KORE_JSON_ERR_NOT_FOUND         10 // Элемент не найден
#define KORE_JSON_ERR_TYPE_MISMATCH     11 // Несовпадение типов
```
Эти ошибки используются при обработке JSON.

## **1.3. Поиск и создание JSON-объектов**
```c
#define kore_json_find_object(j, p)    kore_json_find(j, p, KORE_JSON_TYPE_OBJECT)
#define kore_json_find_array(j, p)     kore_json_find(j, p, KORE_JSON_TYPE_ARRAY)
#define kore_json_find_string(j, p)    kore_json_find(j, p, KORE_JSON_TYPE_STRING)
```
Макросы для поиска элементов JSON.

```c
#define kore_json_create_object(o, n) kore_json_create_item(o, n, KORE_JSON_TYPE_OBJECT)
#define kore_json_create_array(o, n) kore_json_create_item(o, n, KORE_JSON_TYPE_ARRAY)
#define kore_json_create_string(o, n, v) kore_json_create_item(o, n, KORE_JSON_TYPE_STRING, v)
```
Макросы для создания новых JSON-объектов.

## **1.4. Структура данных JSON**
```c
struct kore_json {
    const u_int8_t   *data;   // Данные JSON
    int              depth;   // Текущая глубина парсинга
    size_t           length;  // Длина JSON-данных
    size_t           offset;  // Текущий сдвиг при парсинге
    struct kore_buf  tmpbuf;  // Временный буфер
    struct kore_json_item *root; // Корневой элемент
};
```
Это основная структура для парсинга JSON.

---

# **2. Работа процессов и IPC**
(Разбор второй части кода)

## **2.1. Типы процессов**
```c
#define KORE_WORKER_KEYMGR_IDX  0  // Индекс процесса Key Manager
#define KORE_WORKER_ACME_IDX    1  // Индекс процесса ACME (сертификаты)
#define KORE_WORKER_BASE        2  // Обычные воркеры
#define KORE_WORKER_KEYMGR      2000 // Процесс Key Manager
#define KORE_WORKER_ACME        2001 // Процесс ACME
#define KORE_WORKER_MAX         UCHAR_MAX // Максимальное количество воркеров
```
- **KEYMGR (2000)** – процесс управления ключами (SSL/TLS).
- **ACME (2001)** – процесс автоматического обновления сертификатов.
- **BASE (2)** – основные рабочие процессы.

## **2.2. Политика работы процессов**
```c
#define KORE_WORKER_POLICY_RESTART   1  // Перезапуск при завершении
#define KORE_WORKER_POLICY_TERMINATE 2  // Завершение без перезапуска
```

## **2.3. IPC: сообщения между процессами**
```c
struct kore_msg {
    u_int8_t id;      // ID сообщения
    u_int16_t src;    // Отправитель
    u_int16_t dst;    // Получатель
    size_t length;    // Длина данных
};
```
Используется для передачи сообщений между процессами.

```c
#define KORE_MSG_WEBSOCKET      1  // WebSocket сообщение
#define KORE_MSG_KEYMGR_REQ     2  // Запрос к менеджеру ключей
#define KORE_MSG_KEYMGR_RESP    3  // Ответ от менеджера ключей
#define KORE_MSG_SHUTDOWN       4  // Завершение работы
#define KORE_MSG_CERTIFICATE    7  // Сертификат
#define KORE_MSG_CERTIFICATE_REQ 8 // Запрос сертификата
```
Некоторые сообщения в IPC.

```c
#define KORE_MSG_PARENT     1000 // Сообщение главному процессу
#define KORE_MSG_WORKER_ALL 1001 // Сообщение всем воркерам
```
Предопределённые получатели.

---

## **3. Глобальные переменные**
```c
extern pid_t kore_pid;   // PID главного процесса
extern int   kore_quit;  // Флаг завершения работы
extern int   kore_quiet; // Флаг тихого режима
extern int   skip_chroot; // Отключение chroot
extern int   skip_runas; // Отключение смены пользователя
extern int   kore_foreground; // Запуск в foreground-режиме
extern char *kore_pidfile; // Файл с PID процесса
```
Глобальные переменные, управляющие процессом Kore.

```c
extern u_int8_t  worker_count;          // Количество воркеров
extern u_int32_t worker_max_connections; // Максимальное число соединений
extern u_int32_t kore_socket_backlog;   // Очередь входящих соединений
```
Переменные, связанные с воркерами и сервером.

---

# **Вывод**
1. **JSON в Kore**
    - Парсинг JSON реализован через `kore_json`.
    - Есть поддержка поиска и создания объектов.
    - Используются битовые флаги для типов данных.

2. **Работа процессов и IPC**
    - Kore использует **воркеры** для обработки запросов.
    - **Key Manager (2000)** управляет ключами.
    - **ACME (2001)** обновляет сертификаты.
    - IPC реализован через структуру `kore_msg`.
    - Сообщения можно отправлять главному процессу (`KORE_MSG_PARENT`) или всем воркерам (`KORE_MSG_WORKER_ALL`).



---

# **1. Определения процессов**
```c
#define KORE_WORKER_KEYMGR_IDX  0
#define KORE_WORKER_ACME_IDX    1
#define KORE_WORKER_BASE        2
#define KORE_WORKER_KEYMGR      2000
#define KORE_WORKER_ACME        2001
#define KORE_WORKER_MAX         UCHAR_MAX
```
- **KORE_WORKER_KEYMGR_IDX (0)** – индекс процесса **Key Manager**, который управляет сертификатами и ключами.
- **KORE_WORKER_ACME_IDX (1)** – индекс процесса **ACME**, который занимается получением и обновлением сертификатов.
- **KORE_WORKER_BASE (2)** – все обычные воркеры.
- **KORE_WORKER_KEYMGR (2000)** – процесс **Key Manager**.
- **KORE_WORKER_ACME (2001)** – процесс **ACME**.
- **KORE_WORKER_MAX (UCHAR_MAX)** – максимальное количество воркеров.

Это используется для управления разными типами процессов в Kore.

---

# **2. Политики работы воркеров**
```c
#define KORE_WORKER_POLICY_RESTART   1
#define KORE_WORKER_POLICY_TERMINATE 2
```
- **KORE_WORKER_POLICY_RESTART** – процесс будет перезапущен, если завершится.
- **KORE_WORKER_POLICY_TERMINATE** – процесс не перезапускается при завершении.

Это задаёт стратегию работы воркеров.

---

# **3. IPC (межпроцессное взаимодействие)**
## **3.1. Определение сообщений**
```c
#define KORE_MSG_WEBSOCKET      1
#define KORE_MSG_KEYMGR_REQ     2
#define KORE_MSG_KEYMGR_RESP    3
#define KORE_MSG_SHUTDOWN       4
#define KORE_MSG_ENTROPY_REQ    5
#define KORE_MSG_ENTROPY_RESP   6
#define KORE_MSG_CERTIFICATE    7
#define KORE_MSG_CERTIFICATE_REQ 8
#define KORE_MSG_CRL            9
#define KORE_MSG_ACCEPT_AVAILABLE 10
#define KORE_PYTHON_SEND_OBJ    11
#define KORE_MSG_WORKER_LOG     12
#define KORE_MSG_FATALX         13
#define KORE_MSG_ACME_BASE      100
#define KORE_MSG_APP_BASE       200
```
Это идентификаторы сообщений, которые могут передаваться между процессами:
- **KORE_MSG_WEBSOCKET (1)** – сообщение для WebSocket.
- **KORE_MSG_KEYMGR_REQ (2)** – запрос к **Key Manager**.
- **KORE_MSG_KEYMGR_RESP (3)** – ответ от **Key Manager**.
- **KORE_MSG_SHUTDOWN (4)** – сообщение о завершении работы.
- **KORE_MSG_CERTIFICATE (7)** – сообщение с сертификатом.
- **KORE_MSG_CERTIFICATE_REQ (8)** – запрос на сертификат.
- **KORE_MSG_WORKER_LOG (12)** – логирование воркеров.
- **KORE_MSG_APP_BASE (200)** – сообщения для приложений (начинаются с 201).

---

## **3.2. Куда можно отправлять сообщения**
```c
#define KORE_MSG_PARENT     1000
#define KORE_MSG_WORKER_ALL 1001
```
- **KORE_MSG_PARENT (1000)** – отправить сообщение главному процессу.
- **KORE_MSG_WORKER_ALL (1001)** – отправить сообщение всем воркерам.

---

# **4. Структуры данных**
## **4.1. Структура сообщения между процессами**
```c
struct kore_msg {
    u_int8_t    id;     // ID сообщения
    u_int16_t   src;    // Отправитель (номер процесса)
    u_int16_t   dst;    // Получатель (номер процесса)
    size_t      length; // Длина данных
};
```
- **id** – тип сообщения (например, `KORE_MSG_WEBSOCKET`).
- **src** – ID процесса-отправителя.
- **dst** – ID процесса-получателя.
- **length** – размер данных.

Эта структура используется для передачи данных между процессами.

---

## **4.2. Запрос к Key Manager**
```c
struct kore_keyreq {
    int        padding;
    char       domain[KORE_DOMAINNAME_LEN + 1];
    size_t     data_len;
    u_int8_t   data[];
};
```
- **padding** – просто отступ (может быть не использоваться).
- **domain** – имя домена (например, `"example.com"`).
- **data_len** – размер данных.
- **data** – сами данные.

Эта структура используется для работы с SSL/TLS сертификатами.

---

## **4.3. Передача сертификатов**
```c
struct kore_x509_msg {
    char       domain[KORE_DOMAINNAME_LEN + 1];
    size_t     data_len;
    u_int8_t   data[];
};
```
Очень похожа на `kore_keyreq`, но предназначена **для сертификатов**.

---

# **5. Глобальные переменные**
```c
extern pid_t   kore_pid;   // PID главного процесса
extern int     kore_quit;  // Флаг завершения работы
extern int     kore_quiet; // Флаг "тихого" режима
extern int     skip_chroot; // Отключение chroot
extern int     skip_runas;  // Отключение смены пользователя
extern int     kore_foreground; // Запуск в foreground-режиме
extern char    *kore_pidfile; // Путь к файлу с PID
```
Эти переменные управляют работой Kore.

```c
extern u_int8_t  worker_count;          // Количество воркеров
extern u_int32_t worker_max_connections; // Максимальное число соединений
extern u_int32_t kore_socket_backlog;   // Очередь входящих соединений
```
Эти переменные отвечают за работу серверной части.

---

# **Вывод**
1. **Процессы**
    - Есть три типа: **Key Manager (2000), ACME (2001), обычные воркеры (2)**.
    - Воркеры могут **перезапускаться или завершаться** после работы.

2. **IPC (межпроцессное взаимодействие)**
    - Сообщения передаются между процессами с помощью структуры `kore_msg`.
    - Можно **отправлять** запросы **Key Manager-у** (`KORE_MSG_KEYMGR_REQ`) и получать ответы (`KORE_MSG_KEYMGR_RESP`).
    - Есть **запросы на сертификаты** (`KORE_MSG_CERTIFICATE_REQ`).

3. **Глобальные переменные**
    - Определяют настройки сервера (`worker_count`, `worker_max_connections`).
    - Управляют **логикой работы** (`kore_quit`, `kore_foreground`).

Этот код — основа для **управления процессами и IPC** в Kore.



Дальше идет список экспортируемых функций он содержит большое количество различных функций для работы
с сервером, обработкой соединений, TLS, логированием, парсингом данных и многими другими аспектами. 
Вот их краткое описание по категориям:

### 1. **Основные серверные функции**:
- **kore_signal**: обработка сигналов.
- **kore_shutdown**: завершение работы сервера.
- **kore_server_create**: создание нового сервера.
- **kore_server_lookup**: поиск сервера по имени.
- **kore_server_closeall**: закрытие всех серверных соединений.
- **kore_server_cleanup**: очистка ресурсов сервера.
- **kore_server_free**: освобождение ресурсов сервера.

### 2. **Работа с соединениями**:
- **kore_connection_init**: инициализация соединений.
- **kore_connection_cleanup**: очистка соединений.
- **kore_connection_accept**: принятие соединений.
- **kore_connection_disconnect**: отключение соединения.
- **kore_connection_start_idletimer**: запуск таймера бездействия для соединения.
- **kore_connection_check_timeout**: проверка тайм-аута соединения.

### 3. **Обработка TLS/SSL**:
- **kore_tls_init**: инициализация TLS.
- **kore_tls_cleanup**: очистка TLS.
- **kore_tls_dh_check**: проверка диффи-Хеллмана.
- **kore_tls_supported**: проверка поддержки TLS.
- **kore_tls_keymgr_init**: инициализация менеджера ключей TLS.
- **kore_tls_connection_accept**: принятие TLS-соединения.
- **kore_tls_write**: отправка данных через TLS.

### 4. **Обработка сообщений**:
- **kore_msg_init**: инициализация системы сообщений.
- **kore_msg_send**: отправка сообщения.
- **kore_msg_register**: регистрация обработчика сообщений.

### 5. **Обработка файлов и маршрутов**:
- **kore_filemap_init**: инициализация карты файлов.
- **kore_filemap_resolve_paths**: разрешение путей файлов.
- **kore_route_create**: создание маршрута.
- **kore_route_lookup**: поиск маршрута.

### 6. **Логирование**:
- **kore_log_init**: инициализация логирования.
- **kore_log_file**: логирование в файл.
- **kore_accesslog_init**: инициализация логирования доступа.
- **kore_accesslog_run**: выполнение логирования доступа.

### 7. **Память и пул памяти**:
- **kore_malloc**: выделение памяти.
- **kore_free**: освобождение памяти.
- **kore_pool_get**: получение из пула памяти.
- **kore_pool_put**: возвращение в пул памяти.

### 8. **Работа с JSON**:
- **kore_json_parse**: парсинг JSON.
- **kore_json_cleanup**: очистка JSON.
- **kore_json_create_item**: создание элемента JSON.
- **kore_json_find**: поиск элемента в JSON.

### 9. **Таймеры**:
- **kore_timer_init**: инициализация таймеров.
- **kore_timer_run**: запуск таймеров.
- **kore_timer_add**: добавление нового таймера.

### 10. **Сетевые функции**:
- **net_init**: инициализация сетевых функций.
- **net_send**: отправка данных через сеть.
- **net_recv**: получение данных из сети.

### 11. **Платформенные функции (для разных ОС)**:
- **kore_platform_init**: инициализация платформенных функций.
- **kore_platform_sandbox**: создание песочницы.
- **kore_platform_event_init**: инициализация обработки событий.

### 12. **Функции для работы с веб-сокетами**:
- **kore_websocket_handshake**: выполнение хэндшейка для веб-сокетов.
- **kore_websocket_send**: отправка данных через веб-сокет.
- **kore_websocket_broadcast**: широковещательная отправка через веб-сокет.

### 13. **Функции для работы с авторизацией**:
- **kore_auth_run**: запуск процесса авторизации.
- **kore_auth_cookie**: работа с cookie для авторизации.
- **kore_auth_request**: обработка запроса для авторизации.

### 14. **Функции для работы с доменами и модулями**:
- **kore_domain_new**: создание нового домена.
- **kore_domain_lookup**: поиск домена.
- **kore_module_reload**: перезагрузка модуля.

### 15. **Работа с ключами**:
- **kore_keymgr_run**: выполнение работы менеджера ключей.
- **kore_keymgr_cleanup**: очистка менеджера ключей.

### 16. **Обработка ошибок**:
- **fatal**: завершение работы с ошибкой.
- **fatalx**: завершение работы с ошибкой без возврата.

### 17. **Функции для работы с памятью и строками**:
- **kore_strdup**: создание копии строки.
- **kore_strlcpy**: безопасное копирование строки.
- **kore_mem_zero**: обнуление памяти.

### 18. **Функции для работы с сетью и буферами**:
- **kore_buf_alloc**: выделение памяти под буфер.
- **kore_buf_append**: добавление данных в буфер.
- **kore_buf_release**: освобождение данных из буфера.

---

Это общий список экспортируемых функций в коде, каждая из которых служит для конкретных целей, таких как обработка соединений, работа с TLS, управление памятью, логирование и многие другие задачи, характерные для работы веб-сервера.