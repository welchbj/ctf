# Who is That in That Mirror

This was a web challenge that took me a while, but ended up having a rather simple solution.

Almost every input on the target web application does not sanitize the data that gets passed to SQL queries. However, all inputs seem to filter out `'";`, preventing you from attempting a stacked query. Eventually, I was able to determine that the base64-encoded `uu` cookie used for authentication is injectable, and does not filter any of these special characters out. We are then able to perform a stacked query with this injection to insert a new record into the `products` table. After some experiementation, you can determine that there is command injection in the `image` column of the `products` table, which can be used to pop a reverse shell.
