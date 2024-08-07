import asyncio

async def task():
    # Some sensitive data
    sensitive_data = "Sensitive Information"
    # Perform some asynchronous operation
    await asyncio.sleep(1)
    return sensitive_data

async def main():
    task_obj = asyncio.create_task(task())
    
    # Simulating an attacker swapping the current task
    original_task = asyncio.current_task()
    asyncio._swap_current_task(task_obj)
    
    try:
        # Perform some operations as the swapped task
        result = await task_obj
        print(f"Task result: {result}")
    finally:
        # Restore the original task
        asyncio._swap_current_task(original_task)

asyncio.run(main())
