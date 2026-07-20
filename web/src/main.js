// Operator console. Calls two endpoints: create an account, and read a balance.
//
// Requests go through the dev-server proxy at /api/*, so no CORS round trip is
// needed when the page is served by `npm start`.
//
// INTENTIONALLY VULNERABLE TESTBED - see the repository README.

/* global $, _ */

(function () {
  "use strict";

  var API_BASE = _.get(window, "LEDGER_CONFIG.apiBase", "/api");

  function render(value) {
    $("#output").text(
      _.isString(value) ? value : JSON.stringify(value, null, 2)
    );
  }

  // Money is carried as integer minor units. Format it for display only.
  function formatAmount(minorUnits, currency) {
    var major = (minorUnits / 100).toFixed(2);
    return _.compact([currency, major]).join(" ");
  }

  function call(path, options) {
    return $.ajax(
      _.defaults(options || {}, {
        url: API_BASE + path,
        contentType: "application/json",
        dataType: "json",
      })
    ).then(
      function (body) {
        return body;
      },
      function (xhr) {
        var detail = _.get(xhr, "responseJSON.detail", "request failed");
        return $.Deferred().reject(new Error(detail));
      }
    );
  }

  // Endpoint 1: POST /accounts
  $("#create-account").on("click", function () {
    var owner = $.trim($("#owner").val());
    if (!owner) {
      render("Enter an owner name first.");
      return;
    }

    render("Creating account...");
    call("/accounts", {
      method: "POST",
      data: JSON.stringify({ owner: owner }),
    })
      .then(function (account) {
        $("#account-id").val(account.id);
        render(account);
      })
      .catch(function (error) {
        render("Error: " + error.message);
      });
  });

  // Endpoint 5: GET /accounts/{id}/balance
  $("#fetch-balance").on("click", function () {
    var accountId = $.trim($("#account-id").val());
    if (!accountId) {
      render("Enter an account ID first.");
      return;
    }

    render("Fetching balance...");
    call("/accounts/" + encodeURIComponent(accountId) + "/balance")
      .then(function (result) {
        render(
          _.assign({}, result, {
            formatted: formatAmount(result.balance, result.currency),
          })
        );
      })
      .catch(function (error) {
        render("Error: " + error.message);
      });
  });
})();
