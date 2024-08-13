import heapq

def vulnerable_function():
    heap = [1, 2, 3]
    heapq.heappushpop(heap, 4)  # This line is vulnerable
    return heap