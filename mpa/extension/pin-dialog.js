const form = document.getElementById("pin-form");
const pinInput = document.getElementById("pin");
const cancelButton = document.getElementById("cancel");

function sendResult(pin) {
  chrome.runtime.sendMessage({
    type: "pin-dialog-result",
    pin
  }, () => {
    window.close();
  });
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  sendResult(pinInput.value);
});

cancelButton.addEventListener("click", () => {
  sendResult(null);
});

