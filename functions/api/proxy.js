export async function onRequest(context) {
  const GAS_URL = 'https://script.google.com/macros/s/AKfycbxXpcDus7WSGZdzO9j3YgshTXouEkgMLFRgMLdePHS9rL_8eSnmJcmrJ77auoOoeeMxmA/exec';

  if (context.request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
      }
    });
  }

  const body = await context.request.text();
  const parsed = JSON.parse(body);

  // Handle Discord webhook — route through Cloudflare instead of GAS
  if (parsed.action === 'sendLog') {
    await fetch(parsed.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(parsed.payload)
    });
    return new Response(JSON.stringify({ status: 'ok' }), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
    });
  }

  // Everything else → forward to GAS
  const response = await fetch(GAS_URL, {
    method: 'POST',
    body: body,
    redirect: 'follow',
    headers: { 'Content-Type': 'application/json' }
  });
  const data = await response.text();
  return new Response(data, {
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}
