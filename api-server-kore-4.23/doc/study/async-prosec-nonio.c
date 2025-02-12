/*
Пример с **неблокирующим I/O (non-blocking I/O)** предполагает использование подхода, при котором операции выполняются асинхронно и не блокируют выполнение других задач. Такой подход может быть использован для обработки множества операций одновременно, не ожидая завершения одной операции перед началом следующей.

В C можно симулировать подобное поведение с помощью неблокирующего ввода-вывода через стандартные механизмы, такие как использование **`select`** или **`poll`** для неблокирующего чтения и записи. Для простоты мы будем использовать стандартный неблокирующий режим работы с потоками, при этом оставим структуру, имитирующую банковские операции.

### Пример с неблокирующими операциями

Представим, что у нас есть банк, который обрабатывает переводы средств между счетами, и мы используем неблокирующий механизм для обработки транзакций.
*/

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#define NUM_WORKERS 3
#define NUM_OPERATIONS 5

// Структура банковской операции
typedef struct {
    int operation_id;
    double amount;  // Сумма операции
    int account_from;  // Счёт, с которого списываются средства
    int account_to;    // Счёт, на который зачисляются средства
} operation_t;

// Очередь операций
operation_t operation_queue[NUM_OPERATIONS];
int operation_count = 0;
pthread_mutex_t operation_mutex = PTHREAD_MUTEX_INITIALIZER;  // Мьютекс для синхронизации доступа к очереди операций

// Функция для добавления операции в очередь
void add_operation_to_queue(int operation_id, double amount, int account_from, int account_to) {
    pthread_mutex_lock(&operation_mutex);
    if (operation_count < NUM_OPERATIONS) {
        operation_queue[operation_count].operation_id = operation_id;
        operation_queue[operation_count].amount = amount;
        operation_queue[operation_count].account_from = account_from;
        operation_queue[operation_count].account_to = account_to;
        operation_count++;
    }
    pthread_mutex_unlock(&operation_mutex);
}

// Симуляция неблокирующей операции перевода
int non_blocking_transfer(int account_from, int account_to, double amount) {
    // Эмуляция неблокирующего ввода/вывода
    int ret = rand() % 2;  // 50% шанс, что операция пройдет успешно
    if (ret == 0) {
        return -1;  // Ошибка
    }
    return 0;  // Успех
}

// Функция для выполнения банковской операции
void* worker_function(void* arg) {
    while (1) {
        pthread_mutex_lock(&operation_mutex);
        if (operation_count > 0) {
            operation_t operation = operation_queue[0];
            // Сдвигаем операции в очереди
            for (int i = 0; i < operation_count - 1; i++) {
                operation_queue[i] = operation_queue[i + 1];
            }
            operation_count--;
            pthread_mutex_unlock(&operation_mutex);

            printf("Worker %ld is processing operation %d: Transfer $%.2f from account %d to account %d\n",
                   (long)arg, operation.operation_id, operation.amount, operation.account_from, operation.account_to);

            // Неблокирующая операция перевода
            int result = non_blocking_transfer(operation.account_from, operation.account_to, operation.amount);
            if (result == 0) {
                printf("Transfer of $%.2f from account %d to account %d completed successfully.\n",
                       operation.amount, operation.account_from, operation.account_to);
            } else {
                printf("Transfer of $%.2f from account %d to account %d failed (non-blocking I/O).\n",
                       operation.amount, operation.account_from, operation.account_to);
            }
            sleep(1);  // Симуляция времени на выполнение операции
        } else {
            pthread_mutex_unlock(&operation_mutex);
            sleep(1);  // Ожидаем новые операции
        }
    }
    return NULL;
}

// Цикл событий (эмуляция поступления банковских операций)
void event_loop() {
    for (int i = 1; i <= NUM_OPERATIONS; i++) {
        double amount = (i % 2 == 0) ? 500.0 : 1000.0;  // Разные суммы для операций
        int account_from = i;  // Счёт отправителя
        int account_to = (i % 2 == 0) ? i - 1 : i + 1;  // Счёт получателя
        add_operation_to_queue(i, amount, account_from, account_to);
        printf("Operation %d added to queue: Transfer $%.2f from account %d to account %d\n",
               i, amount, account_from, account_to);
        sleep(1);  // Симуляция времени между поступлением операций
    }
}

int main() {
    pthread_t workers[NUM_WORKERS];

    // Запуск воркеров
    for (long i = 0; i < NUM_WORKERS; i++) {
        pthread_create(&workers[i], NULL, worker_function, (void*)i);
    }

    // Запуск цикла событий
    event_loop();

    // Ожидание завершения работы воркеров
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    return 0;
}
/*
### Что изменилось:
1. **Неблокирующий перевод**:
   - Функция `non_blocking_transfer` эмулирует неблокирующий I/O. Мы имитируем случайный успех или неудачу операции перевода (с шансом 50%).
   - В реальном мире, неблокирующие операции могут включать обращение к базе данных или сетевым операциям, но здесь это моделируется через случайный результат.

2. **Асинхронная обработка**:
   - Воркеры обрабатывают транзакции, не блокируя выполнение программы, даже если операция не может быть выполнена немедленно.
   - Мы продолжаем выполнять другие операции, даже если текущая не прошла (например, из-за ошибок или задержек).

3. **Ожидания**:
   - Задержки с помощью `sleep(1)` симулируют время, которое воркеры тратят на ожидание новых операций или на обработку текущих.

### Пример из жизни:
Представь, что банк обрабатывает транзакции между счётами. Каждая операция может занимать время из-за внешних факторов (например, связь с базой данных или внешними системами). Вместо того чтобы блокировать воркера и ждать, пока операция будет завершена, мы используем неблокирующий I/O, позволяя другим воркерам продолжать обработку других операций, пока одна не завершится.

Этот код является моделью того, как можно работать с асинхронной обработкой банковских транзакций с использованием неблокирующих операций.

Если нужно подробнее разъяснить или что-то добавить — не стесняйтесь спрашивать!

 */