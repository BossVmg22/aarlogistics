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
  const response = await fetch(GAS_URL, { method: 'POST', body: body });
  const data = await response.text();

  return new Response(data, {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*'
    }
  });
}