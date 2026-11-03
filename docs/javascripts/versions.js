(function () {
  var root = document.getElementById("ezcve-versions");
  if (!root) {
    return;
  }

  var releasesUrl = "https://github.com/mrjoshuap/ansible-ezcve/releases";
  var api = "https://api.github.com/repos/mrjoshuap/ansible-ezcve/releases?per_page=20";

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function card(title, body) {
    return (
      '<section class="ezcve-version-card"><h3>' +
      title +
      "</h3>" +
      body +
      "</section>"
    );
  }

  function versionFromTag(tagName) {
    return String(tagName).replace(/^v/, "");
  }

  function devRange(version) {
    var match = /^(\d+\.\d+\.\d+)-dev\./.exec(version);
    if (!match) {
      return "";
    }
    return ">=" + match[1] + "-dev,<" + match[1];
  }

  function showFallback() {
    root.innerHTML =
      '<p>Current release versions could not be loaded. See <a href="' +
      releasesUrl +
      '">GitHub Releases</a>.</p>';
  }

  fetch(api, { headers: { Accept: "application/vnd.github+json" } })
    .then(function (response) {
      if (!response.ok) {
        throw new Error(String(response.status));
      }
      return response.json();
    })
    .then(function (releases) {
      if (!Array.isArray(releases)) {
        throw new Error("unexpected payload");
      }

      var stable = null;
      var development = null;
      releases.forEach(function (item) {
        if (!item || item.draft || !item.tag_name) {
          return;
        }
        if (!item.prerelease && !stable) {
          stable = item;
        }
        if (item.prerelease && !development) {
          development = item;
        }
      });

      var html = "";
      if (stable) {
        var stableVersion = versionFromTag(stable.tag_name);
        html += card(
          "Stable",
          "<p><a href=\"" +
            escapeHtml(stable.html_url) +
            '"><code>' +
            escapeHtml(stableVersion) +
            "</code></a></p>" +
            "<pre><code>ansible-galaxy collection install 'mrjoshuap.ezcve:==" +
            escapeHtml(stableVersion) +
            "'</code></pre>" +
            "<p>A requirements range stays on stable releases:</p>" +
            "<pre><code>collections:\n" +
            "  - name: mrjoshuap.ezcve\n" +
            '    version: "&gt;=1.0.0"</code></pre>'
        );
      } else {
        html += card(
          "Stable",
          '<p>No stable release is published yet. See <a href="' +
            releasesUrl +
            '">GitHub Releases</a>.</p>'
        );
      }

      if (development) {
        var devVersion = versionFromTag(development.tag_name);
        var range = devRange(devVersion);
        var devHtml =
          "<p><a href=\"" +
          escapeHtml(development.html_url) +
          '"><code>' +
          escapeHtml(devVersion) +
          "</code></a></p>" +
          "<pre><code>ansible-galaxy collection install 'mrjoshuap.ezcve:==" +
          escapeHtml(devVersion) +
          "'</code></pre>";
        if (range) {
          devHtml +=
            "<pre><code>ansible-galaxy collection install mrjoshuap.ezcve --pre '" +
            escapeHtml(range) +
            "'</code></pre>";
        }
        html += card("Development", devHtml);
      } else {
        html += card(
          "Development",
          '<p>No development prerelease is published yet. See <a href="' +
            releasesUrl +
            '">GitHub Releases</a>.</p>'
        );
      }

      root.innerHTML = html;
    })
    .catch(function () {
      showFallback();
    });
})();
