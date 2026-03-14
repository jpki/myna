// modify navigator.userAgent
{
  const ua = navigator.userAgent;
  const fakeUserAgent = ua
    .replace(/Linux\s*[^;)]*/i, "Windows NT 10.0; Win64; x64")
    .replace(/X11;\s*/i, "")
  Object.defineProperty(navigator, "userAgent", {
    get: () => fakeUserAgent,
    configurable: true,
  });
}

// modify navigator.userAgentData
if (navigator.userAgentData) {
  const original = navigator.userAgentData;
  const fakeUA = {
    brands: original.brands,
    mobile: original.mobile,
    platform: "Windows",
    getHighEntropyValues(hints) {
      return original.getHighEntropyValues(hints).then((values) => {
        values.platform = "Windows";
        values.platformVersion = "10.0.0";
        return values;
      });
    },
    toJSON() {
      return {
        brands: this.brands,
        mobile: this.mobile,
        platform: this.platform,
      };
    },
  };
  Object.setPrototypeOf(fakeUA, NavigatorUAData.prototype);
  Object.defineProperty(navigator, "userAgentData", {
    get: () => fakeUA,
    configurable: true,
  });
}

