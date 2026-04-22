"use strict";

(async () => {
  const windowId = (await chrome.windows.getCurrent()).id;

  const data = await chrome.runtime.sendMessage({ type: "get-approval-data" });
  if (data) {
    document.getElementById("operation").textContent =
      data.operationType === "create" ? "登録" : "認証";
    document.getElementById("rpId").textContent = data.rpId || "-";
    document.getElementById("userName").textContent = data.userDisplayName || "-";
    if (data.errorMessage) {
      document.getElementById("error").textContent = data.errorMessage;
    }
  }

  const pinInput = document.getElementById("pin");
  const approveBtn = document.getElementById("approve");

  const updateApprove = () => {
    approveBtn.disabled = !/^\d{4}$/.test(pinInput.value);
  };
  pinInput.addEventListener("input", updateApprove);
  pinInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !approveBtn.disabled) {
      approveBtn.click();
    }
  });

  approveBtn.addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "approval-result",
      result: "approved",
      pin: pinInput.value,
      windowId,
    });
  });

  document.getElementById("reject").addEventListener("click", () => {
    chrome.runtime.sendMessage({
      type: "approval-result",
      result: "rejected",
      windowId,
    });
  });
})();
