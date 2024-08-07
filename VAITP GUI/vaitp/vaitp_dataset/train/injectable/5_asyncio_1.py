#Explanation:
    #Sensitive Data: The task function contains sensitive data.
    #Task Management: The main function creates a task and awaits it directly instead of using any internal methods to swap tasks.
    #Safe Awaiting: By using await task_obj, we ensure that we are following the documented and safe practices of managing asynchronous tasks in Python.

import asyncio

async def task():
    # Some sensitive data
    sensitive_data = "Sensitive Information"
    # Perform some asynchronous operation
    await asyncio.sleep(1)
    return sensitive_data

async def main():
    task_obj = asyncio.create_task(task())
    
    # Instead of swapping the task, just await it
    try:
        # Perform some operations as the awaited task
        result = await task_obj
        print(f"Task result: {result}")
    except Exception as e:
        print(f"Task raised an exception: {e}")

asyncio.run(main())
