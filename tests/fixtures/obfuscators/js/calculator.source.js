(function() {
    var Calculator = {
        add: function(a, b) { return a + b; },
        subtract: function(a, b) { return a - b; },
        multiply: function(a, b) { return a * b; },
        divide: function(a, b) { return b !== 0 ? a / b : 'Error'; }
    };

    console.log('10 + 5 =', Calculator.add(10, 5));
    console.log('10 - 5 =', Calculator.subtract(10, 5));
    console.log('10 * 5 =', Calculator.multiply(10, 5));
    console.log('10 / 5 =', Calculator.divide(10, 5));
})();
