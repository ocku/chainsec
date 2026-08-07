class SafeEvaluator:
    def eval(self, expression: str) -> str:
        return expression


def evaluate(expression: str) -> str:
    return expression


text = "eval('not executed')"
result = SafeEvaluator().eval(evaluate(text))
