ENTRY(_start);

SECTIONS
{
	. = ALIGN(16);

	.text :
	{
		*(.entry)
		*(.text)
		*(.rdata)
	}
	/DISCARD/ :
	{
		*(.edata)
		*(.xdata)
		*(.pdata)
	}
	.others :
	{
		*(*)
	}
}

ASSERT(SIZEOF(.others) == 0, "There are other sections");