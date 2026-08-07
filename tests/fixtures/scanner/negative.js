const source = "eval('not executed')";
const evaluator = {
  eval(value) {
    return value;
  },
};

function Functional(value) {
  return evaluator.eval(value);
}

Functional(source);
