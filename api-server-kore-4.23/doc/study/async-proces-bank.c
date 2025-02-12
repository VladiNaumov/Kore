#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

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
            sleep(3);  // Симуляция времени на выполнение операции
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
1. **Банковская операция**:
   - Мы создали структуру `operation_t`, которая теперь включает информацию о том, с какого счёта списываются средства (`account_from`) и на какой счёт они переводятся (`account_to`).
   - Операция теперь выглядит как перевод средств между двумя счётами.

2. **Цикл событий**:
   - В цикле событий операции добавляются в очередь с заданными суммами и назначением счёта. Каждый перевод имеет разные суммы и счёта отправителя/получателя.
   - Пример: Транзакция может быть переводом $500 с одного счёта на другой, с разными счётами отправителя и получателя.

3. **Обработка операций**:
   - Воркеры (потоки) обрабатывают каждую транзакцию, выполняя "перевод" между счётами, с симуляцией времени обработки с помощью `sleep(3)`.

### Пример из жизни:
Представь, что в банке сотрудники (воркеры) обрабатывают поступающие запросы на переводы средств между счетами. Эти запросы поступают с определенным интервалом времени (например, один запрос в секунду). Каждый запрос описывает перевод определённой суммы с одного счёта на другой. Воркеры выполняют транзакцию (проверка баланса, списание/зачисление средств), что занимает некоторое время (симулируется задержкой в 3 секунды).

Задержка между запросами (`sleep(1)`) эмулирует время, которое необходимо для поступления новых запросов на транзакции, а задержка в обработке операции (`sleep(3)`) — это время, которое воркер тратит на выполнение перевода.

### Заключение:
Этот код моделирует более реальную банковскую систему, где выполняются переводы средств между счётами, и запросы поступают с задержками. Воркеры обрабатывают операции асинхронно, обеспечивая эффективную обработку поступающих транзакций.

 */