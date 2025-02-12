#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

#define NUM_WORKERS 3
#define NUM_TASKS 5

// Структура задачи
typedef struct {
    int task_id;
} task_t;

// Очередь задач
task_t task_queue[NUM_TASKS];
int task_count = 0;
CRITICAL_SECTION task_critical_section;

// Функция для добавления задачи в очередь
void add_task_to_queue(int task_id) {
    EnterCriticalSection(&task_critical_section);
    if (task_count < NUM_TASKS) {
        task_queue[task_count].task_id = task_id;
        task_count++;
    }
    LeaveCriticalSection(&task_critical_section);
}

// Функция для выполнения задачи
DWORD WINAPI worker_function(LPVOID arg) {
    while (1) {
        EnterCriticalSection(&task_critical_section);
        if (task_count > 0) {
            task_t task = task_queue[0];
            // Сдвигаем задачи в очереди
            for (int i = 0; i < task_count - 1; i++) {
                task_queue[i] = task_queue[i + 1];
            }
            task_count--;
            LeaveCriticalSection(&task_critical_section);

            printf("Worker %ld is processing task %d\n", (long)arg, task.task_id);
            Sleep(1000);  // Симуляция выполнения задачи
        } else {
            LeaveCriticalSection(&task_critical_section);
            Sleep(1000);  // Ожидаем новые задачи
        }
    }
    return 0;
}

// Цикл событий
void event_loop() {
    for (int i = 1; i <= NUM_TASKS; i++) {
        add_task_to_queue(i);
        printf("Task %d added to queue.\n", i);
        Sleep(1000);  // Симуляция задержки между запросами
    }
}

int main() {
    HANDLE workers[NUM_WORKERS];

    // Инициализация критической секции
    InitializeCriticalSection(&task_critical_section);

    // Запуск воркеров
    for (long i = 0; i < NUM_WORKERS; i++) {
        workers[i] = CreateThread(NULL, 0, worker_function, (void*)i, 0, NULL);
    }

    // Запуск цикла событий
    event_loop();

    // Ожидание завершения работы воркеров
    WaitForMultipleObjects(NUM_WORKERS, workers, TRUE, INFINITE);

    // Очистка критической секции
    DeleteCriticalSection(&task_critical_section);

    return 0;
}
/*

### Основные отличия для Windows:
1. **Потоки**:
   - Вместо `pthread_create` используется функция **`CreateThread`**, которая создаёт новый поток.
   - В Windows для синхронизации используется **CRITICAL_SECTION** вместо `pthread_mutex`.
   
2. **Задержки**:
   - Для задержек между операциями используется **`Sleep`** (вместо `sleep` на Unix-подобных системах).

3. **Ожидание завершения потоков**:
   - В Windows для ожидания завершения потоков используется **`WaitForMultipleObjects`**.

### Резюме:
Основные концепции остаются теми же, и сама структура программы не изменяется. Основное отличие заключается в том, как создаются и управляются потоки и синхронизация, так как Windows использует свои собственные API для работы с многозадачностью. Но принцип работы с асинхронной обработкой остаётся тем же, и перенести этот код под Windows не составит большой сложности.

 */