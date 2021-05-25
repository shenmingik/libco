#include <libco/co_closure.h>
#include <libco/co_comm.h>
#include <libco/co_routine.h>

#include <stdlib.h>
#include <cstdio>
#include <queue>
#include <iostream>
using namespace std;

// 资源
struct stTask_t
{
    int id;
};

// 存储资源的队列
struct stEnv_t
{
    stCoCond_t *cond;
    queue<stTask_t *> task_queue;
};

// 生产者
void *Producer(void *args)
{
    co_enable_hook_sys();
    stEnv_t *env = (stEnv_t *)args;
    int id = 0;
    while (true)
    {
        stTask_t *task = (stTask_t *)calloc(1, sizeof(stTask_t));
        task->id = id++;
        env->task_queue.push(task);
        cout << "produce task " << task->id << endl;
        co_cond_signal(env->cond);
        poll(NULL, 0, 1000);
    }
    return NULL;
}

// 消费者
void *Consumer(void *args)
{
    co_enable_hook_sys();
    stEnv_t *env = (stEnv_t *)args;
    while (true)
    {
        if (env->task_queue.empty())
        {
            co_cond_timedwait(env->cond, -1);
            continue;
        }
        stTask_t *task = env->task_queue.front();
        env->task_queue.pop();
        cout << "consume task " << task->id << endl;
        free(task);
    }
    return NULL;
}

int main()
{
    stEnv_t *env = new stEnv_t;
    env->cond = co_cond_alloc();

    stCoRoutine_t *consumer_routine;
    // 创建协程
    co_create(&consumer_routine, nullptr, Consumer, env);
    // 启动协程
    co_resume(consumer_routine);

    stCoRoutine_t *producer_routine;
    co_create(&producer_routine, nullptr, Producer, env);
    co_resume(producer_routine);

    //创建eventloop,事件循环
    co_eventloop(co_get_epoll_ct(), nullptr, nullptr);
    return 0;
}