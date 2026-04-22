"use strict";

(async () => {
  const windowId = (await chrome.windows.getCurrent()).id;

  const data = await chrome.runtime.sendMessage({ type: "get-account-list" });
  if (data) {
    document.getElementById("rpId").textContent = data.rpId;
    const list = document.getElementById("accountList");
    for (const account of data.accounts) {
      const li = document.createElement("li");
      li.className = "account-item";
      const name = document.createElement("span");
      name.className = "account-name";
      name.textContent = account.userDisplayName;
      li.appendChild(name);
      li.addEventListener("click", () => {
        chrome.runtime.sendMessage({
          type: "account-selected",
          userId: account.userId,
          windowId,
        });
      });
      list.appendChild(li);
    }
  }

  document.getElementById("cancel").addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "approval-result",
      result: "rejected",
      windowId,
    });
  });
})();
