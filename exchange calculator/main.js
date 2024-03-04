function calculate() {
    const amount = document.getElementById("amount").value;
    const currency = document.getElementById("currency").value;
    const rates = {
      EUR: 0.85,
      GBP: 0.72,
      JPY: 109.95,
      AUD: 1.3,
      MVR: 15.42
    };
    const result = amount * rates[currency];
    document.getElementById("result").innerHTML = `Result: ${result.toFixed(
      2
    )} ${currency}`;
  }