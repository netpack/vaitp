import heapq

def not_vulnerable_function():
    heap = [1, 2, 3]
    heapq.heappush(heap, 4)  # Instead of heappushpop, use heappush
    heapq.heappop(heap)  # and then heappop
    return heap