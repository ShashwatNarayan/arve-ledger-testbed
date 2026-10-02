# Merchant self-service portal.
#
# Builds the return URLs merchants are sent back to after onboarding. Templated
# URLs come from partner configuration, so they are expanded rather than
# concatenated.

require "addressable/template"

RETURN_TEMPLATE = Addressable::Template.new(
  "https://portal.acme-ledger.example/onboarding/{merchant_id}/complete{?next}"
)

def return_url(merchant_id, next_path = nil)
  RETURN_TEMPLATE.expand(merchant_id: merchant_id, next: next_path).to_s
end
