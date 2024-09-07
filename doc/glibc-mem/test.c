#include <stdio.h>
#include "glib.h"

int main()
{
	g_autoptr(GString) str = g_string_new("hello");
	printf("%s\n", str->str);
	return 0;
}