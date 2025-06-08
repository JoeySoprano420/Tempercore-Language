import threading
from stdlib import TempercoreStdLib as T

class Stack:
    def __init__(self):
        self.stack = []

    def push(self, val):
        self.stack.append(val)
        self.display()

    def pop(self):
        val = self.stack.pop() if self.stack else None
        self.display()
        return val

    def peek(self):
        return self.stack[-1] if self.stack else None

    def display(self):
        print("\n[STACK]")
        for i, item in enumerate(reversed(self.stack)):
            print(f"{len(self.stack) - i}: {item}")
        print("-" * 20)

class Heap:
    def __init__(self):
        self.heap = {}
        self.lock = threading.Lock()

    def allocate(self, name, value):
        with self.lock:
            self.heap[name] = value
            self.display()

    def retrieve(self, name):
        with self.lock:
            return self.heap.get(name, None)

    def delete(self, name):
        with self.lock:
            if name in self.heap:
                del self.heap[name]
                self.display()

    def dump(self):
        with self.lock:
            return dict(self.heap)

    def display(self):
        print("\n[HEAP]")
        for k, v in self.heap.items():
            print(f"{k} => {v}")
        print("-" * 20)

stack = Stack()
heap = Heap()

def run_tempercore_command(cmd):
    tokens = cmd.strip().split()
    if not tokens:
        return

    command = tokens[0]
    if command == "stack":
        if tokens[1] == "push":
            value = " ".join(tokens[2:])
            stack.push(value)
        elif tokens[1] == "pop":
            print("Popped:", stack.pop())
    elif command == "heap":
        action = tokens[1]
        if action == "allocate":
            name = tokens[2]
            value = " ".join(tokens[3:])
            heap.allocate(name, value)
        elif action == "get":
            name = tokens[2]
            print(f"{name} =", heap.retrieve(name))
        elif action == "delete":
            heap.delete(tokens[2])
        elif action == "dump":
            print(heap.dump())
    elif command == "stdlib":
        fn = tokens[1]
        args = [eval(arg) for arg in tokens[2:]]
        if hasattr(T, fn):
            result = getattr(T, fn)(*args)
            print(f"Result of {fn}:", result)
        else:
            print(f"Function {fn} not found in stdlib")
    else:
        print(f"Unknown command: {cmd}")
