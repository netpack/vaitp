print("print range(7)")
for i in range(7):
    print(i)

print("list(range(3,7))")
print(list(range(3,7)))

print("print items of array and position with range() and len()")
a = ["Mary", "had", "a", "nice", "friend", "called", "Jane"]
for i in range(len(a)):
    print(i, a[i])

print("break and continue statements")
for n in range(2,7):
    for x in range(2,n):
        if n % x == 0:
            print(n, 'equals', x, '*', n//x)
            break
    else:
        print(n, 'is a prime')
for n in range(2,7):
    if n%2==0:
        print(n, "is even")
        continue
    print(n, "is not even")

