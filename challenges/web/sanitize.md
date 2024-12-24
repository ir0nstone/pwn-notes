# Sanitize

## Analysis

First we're met with a signin form:

![](<../../.gitbook/assets/image (21).png>)

Let's try some default creds, `admin` and `admin`.

![The Query](<../../.gitbook/assets/image (16).png>)

Below, the query run on the database is shown; this seems like a clear example of **SQL injection**.

## Exploitation

Ultimately, we want to try and log in as a user. To do this, we can try to inject our own SQL.

We know the payload looks like the following:

```sql
select * from users where username = '<username>' AND password = '<password>';
```

We want to trick this into always returning a user, and to do this we'll inject a clause that's **always** true, such as `1=1`.

```sql
admin' OR 1=1
```

That will make the query equal to the following:

```sql
select * from users where username = 'admin' OR 1=1 AND password = 'password';
```

So here, it'll compare the `username` to `admin`, and if it's not the same the check will **still** pass because `1=1`. However, there's a small issue with the `password` still being wrong. To bypass _this_ check, we'll make everything after our injection a **comment** so that the databse ignores it:

```sql
admin' OR 1=1;--
```

That would make the query be:

```sql
select * from users where username = 'admin' OR 1=1;-- AND password = 'password';
```

As you can see, the `username` will always be correct due to the `1=1` and the password check is commented out! Let's try it.

![](<../../.gitbook/assets/image (18).png>)

We still have to input a password because some javascript checks to make sure it's there, but we can fill that with any rubbish. And we get the flag!

`HTB{SQL_1nj3ct1ng_my_w4y_0utta_h3r3}`
