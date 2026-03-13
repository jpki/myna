function addHiddenInput(id, value) {
  const input = document.createElement("input");
  input.id = id;
  input.type = "hidden";
  input.value = value;
  document.body.appendChild(input);
}

const version = chrome.runtime.getManifest().version.split(".")[0];
addHiddenInput("extension-is-installed", version);
addHiddenInput("app-is-installed", "29");

document.addEventListener("launchApp", (event) => {
  const message = JSON.parse(event.detail);
  chrome.runtime.sendMessage({ type: "launch", message: message }, (response) => {
    let detail;
    if (response != null) {
      detail = JSON.stringify(response);
    } else {
      message.result = "1";
      message.errcode = "EW044-C300";
      detail = JSON.stringify(message);
    }
    document.dispatchEvent(new CustomEvent("recvMsg", { bubbles: true, detail: detail }));
  });
});
