class Calculator:
    @staticmethod
    def add(a, b):
        return a + b

    @staticmethod
    def subtract(a, b):
        return a - b

    @staticmethod
    def multiply(a, b):
        return a * b

    @staticmethod
    def divide(a, b):
        return a / b if b != 0 else "Error"


print("10 + 5 =", Calculator.add(10, 5))
print("10 - 5 =", Calculator.subtract(10, 5))
print("10 * 5 =", Calculator.multiply(10, 5))
print("10 / 5 =", Calculator.divide(10, 5))
