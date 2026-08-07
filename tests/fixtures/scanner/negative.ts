interface Evaluator {
  eval(source: string): string;
}

const source: string = "Function('not executed')";
const evaluator: Evaluator = {
  eval(value: string): string {
    return value;
  },
};

export const result = evaluator.eval(source);
