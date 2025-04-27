function pgw_url()
/*
 * Just to kick off dumb crawlers.
 */
{
    const url_parts = [
        'L35wZXRic',
        'mFpbi9wZX',
        'RnYXRld2F',
        '5LmNnaQ=='
    ];
    return window.atob(url_parts.join(''));
}

async function pgw_call()
/*
 * Make request to pet gateway with all arguments of this function.
 * The gateway expects first argument to be method name and second
 * argument to be parameters.
 */
{
    var result;
    while (true) {
        try {
            const response = await fetch(
                pgw_url(),
                {
                    method: 'POST',
                    body: JSON.stringify(arguments),
                    headers: {
                        'Content-Type': 'application/json'
                    }
                }
            );
            if (response.status.toString()[0] === '5') {
                throw new Error(`${pgw_url()}: server error ${response.status} ${response.statusText}`);
            }
            result = await response.json();
            break;
        } catch (error) {
            console.log(`${pgw_url()} error: ${error}, retry in 5 seconds`);
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
    return result
}

(() => {
    pgw_call('log-visitor');
})();
