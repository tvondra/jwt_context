#include "postgres.h"

#include "common/base64.h"

#include "jwt_base64.h"

/*
 * JWT / base64
 *
 * The JWT uses base64 URL encoding, which is not what the built-in API
 * does.
 *
 * The only differences are that URL encoding uses "-_" instead of "+/",
 * and does not use = and newlines at all. Instead of writing a custom
 * encoding, we call the built-in API and then scribble on the strings
 * a little bit.
 */

/*
 * b64url_encode
 *		encode a string in base64, adjust the result to be url-encoded
 */
int
b64url_encode(const uint8 *src, int len, char *dst, int dstlen)
{
	char   *inptr,
		   *outptr,
		   *endptr;
	int		r;

#if PG_VERSION_NUM >= 180000
	r = pg_b64_encode(src, len, dst, dstlen);
#else
	r = pg_b64_encode((const char *) src, len, dst, dstlen);
#endif

	/* built-in encoding failed, can't do anything :-( */
	if (r == -1)
		return -1;

	inptr = outptr = dst;
	endptr = (dst + r);		/* end of encoded string */

	/*
	 * Walk over the encoded string, remove the newlines/padding, replace 
	 * the non-URL characters.
	 */
	while (inptr < endptr)
	{
		/* skip = and \n */
		if (*inptr == '=' || *inptr == '\n')
		{
			inptr++;
			continue;
		}

		/* replace +/ with -_ */
		if (*inptr == '+')
			*outptr = '-';
		else if (*inptr == '/')
			*outptr = '_';
		else
			*outptr = *inptr;

		/* advance the characters */
		inptr++;
		outptr++;
	}

	Assert(inptr == endptr);

	/*
	 * Make sure the string is null-terminated, if we shortened it.
	 *
	 * XXX a bit strange, but we assume the string is null-terminated.
	 */
	if (inptr != outptr)
		*outptr = '\0';

	return (outptr - dst);
}

/*
 * b64url_decode
 *		decode a string encoded using base64 url-encoding
 *
 * To use the built-in base64 API we need to "undo" the url-encoding, in
 * reverse to what b64url_encode does (except the newlines, which are not
 * necessary). We don't want to scribble on the input string directly, so
 * we create a copy first.
 *
 * XXX Does this need to adjust the size of the output buffer, due to the
 * extra padding? Probably not, but not sure.
 */
int
b64url_decode(const char *src, int len, uint8 *dst, int dstlen)
{
	char   *ptr,
		   *endptr;

	/* copy of the input, with space for = padding (up to 3 chars) */
	char   *copy = palloc(len + 3);

	memcpy(copy, src, len);

	/* pointer at the beginning */
	ptr = copy;
	endptr = (copy + len);

	/* walk over the copy of encoded string, replace the chars */
	while (ptr < endptr)
	{
		if (*ptr == '-')
			*ptr = '+';
		else if (*ptr == '_')
			*ptr = '/';

		ptr++;
	}

	Assert(ptr == endptr);

	/* add padding at the end, to make it multiple of 4 chars */
	if ((len % 4) > 0)
	{
		int	padlen = 4 - (len % 4);

		while (padlen > 0)
		{
			*ptr = '=';
			ptr++;
			padlen--;
			len++;
		}
	}

	/* finally call the regular b64 decoding */
#if PG_VERSION_NUM >= 180000
	return pg_b64_decode(copy, len, dst, dstlen);
#else
	return pg_b64_decode(copy, len, (char *) dst, dstlen);
#endif
}
