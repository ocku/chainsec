const decoded = window.atob("Y29uc29sZS5sb2coJ29rJyk=");
const letters = String.fromCharCode(111, 107);
eval(decoded);
Function("value", "return value + 1")(letters);
