// Parse the in-memory VDSO ELF image and print exported function names + addresses.
// Works on 64-bit Linux. Build: gcc -o dump-vdso dump-vdso.c

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <elf.h>
#include <stdint.h>

static int find_vdso_range(void **begin, void **end)
{
	FILE *maps = fopen("/proc/self/maps", "r");
	if (!maps) return -1;
	char buf[1024];
	while (fgets(buf, sizeof(buf), maps)) {
		if (strstr(buf, "[vdso]")) break;
	}
	fclose(maps);
	if (sscanf(buf, "%p-%p", begin, end) != 2) return -1;
	return 0;
}

int main(int argc, char **argv)
{
	int show_symbols = 0;
	if (argc == 2 && strcmp(argv[1], "-s") == 0) show_symbols = 1;
	else if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
		printf("Usage: %s [-s]\n", argv[0]);
		printf("  -s    print symbol names and addresses\n");
		printf("  (no args) write vdso memory to file vdso.so\n");
		return 0;
	}

	void *vdso_begin = NULL, *vdso_end = NULL;
	if (find_vdso_range(&vdso_begin, &vdso_end) < 0) {
		fprintf(stderr, "failed to find [vdso] in /proc/self/maps\n");
		return 1;
	}

	unsigned char *base = (unsigned char*)vdso_begin;
	size_t vdso_size = (unsigned char*)vdso_end - base;

	if (vdso_size < sizeof(Elf64_Ehdr)) {
		fprintf(stderr, "vdso too small\n");
		return 1;
	}

	Elf64_Ehdr *ehdr = (Elf64_Ehdr*)base;
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
		fprintf(stderr, "not an ELF image\n");
		return 1;
	}
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
		fprintf(stderr, "only ELF64 supported by this tool\n");
		return 1;
	}

	Elf64_Phdr *phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
	Elf64_Dyn *dyn = NULL;
	for (int i = 0; i < ehdr->e_phnum; ++i) {
		if (phdr[i].p_type == PT_DYNAMIC) {
			dyn = (Elf64_Dyn*)(base + phdr[i].p_vaddr);
			break;
		}
	}
	if (!dyn) {
		fprintf(stderr, "no PT_DYNAMIC in vdso\n");
		return 1;
	}

	Elf64_Sym *symtab = NULL;
	const char *strtab = NULL;
	uint64_t strsz = 0;
	void *hash = NULL;
	void *gnu_hash = NULL;
	size_t syment = sizeof(Elf64_Sym);

	for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; ++d) {
		switch (d->d_tag) {
		case DT_STRTAB: strtab = (const char*)d->d_un.d_ptr; break;
		case DT_STRSZ: strsz = d->d_un.d_val; break;
		case DT_SYMTAB: symtab = (Elf64_Sym*)d->d_un.d_ptr; break;
		case DT_SYMENT: syment = d->d_un.d_val; break;
		case DT_HASH: hash = (void*)d->d_un.d_ptr; break;
		case DT_GNU_HASH: gnu_hash = (void*)d->d_un.d_ptr; break;
		default: break;
		}
	}

	if (!symtab || !strtab) {
		fprintf(stderr, "no dynamic symtab/strtab found\n");
		return 1;
	}

	// If the DT_* pointers are runtime addresses, they should be valid pointers already.
	// If they look like offsets (small values), convert to offsets relative to base.
	uintptr_t b = (uintptr_t)base;
	uintptr_t e = (uintptr_t)vdso_end;

	uintptr_t symtab_addr = (uintptr_t)symtab;
	uintptr_t strtab_addr = (uintptr_t)strtab;
	uintptr_t hash_addr = (uintptr_t)hash;
	uintptr_t gnu_hash_addr = (uintptr_t)gnu_hash;

	if (symtab_addr < b || symtab_addr >= e) symtab_addr = b + symtab_addr;
	if (strtab_addr < b || strtab_addr >= e) strtab_addr = b + strtab_addr;
	if (hash_addr && (hash_addr < b || hash_addr >= e)) hash_addr = b + hash_addr;
	if (gnu_hash_addr && (gnu_hash_addr < b || gnu_hash_addr >= e)) gnu_hash_addr = b + gnu_hash_addr;

	symtab = (Elf64_Sym*)symtab_addr;
	strtab = (const char*)strtab_addr;
	hash = hash_addr ? (void*)hash_addr : NULL;
	gnu_hash = gnu_hash_addr ? (void*)gnu_hash_addr : NULL;

	size_t symcount = 0;
	if (hash) {
		uint32_t *h = (uint32_t*)hash;
		uint32_t nbucket = h[0];
		uint32_t nchain = h[1];
		symcount = nchain;
	} else if (strsz) {
		// Best-effort: iterate symbols until symbol name index exceeds strtab size.
		// Protect with a reasonable upper bound.
		size_t max = 10000;
		for (size_t i = 0; i < max; ++i) {
			Elf64_Sym *s = (Elf64_Sym*)((char*)symtab + i * syment);
			if ((size_t)s->st_name >= strsz) { symcount = i; break; }
			// if last entry has st_name==0, continue; ensure we don't undercount.
			if (i == max-1) symcount = max;
		}
	} else if (gnu_hash) {
		// Conservative fallback: try counting until a symbol with invalid name.
		size_t max = 10000;
		for (size_t i = 0; i < max; ++i) {
			Elf64_Sym *s = (Elf64_Sym*)((char*)symtab + i * syment);
			const char *name = (const char*)( (char*)strtab + s->st_name );
			if ((uintptr_t)name < b || (uintptr_t)name >= e) { symcount = i; break; }
			if (i == max-1) symcount = max;
		}
	} else {
		// Last fallback: assume a small number
		symcount = 256;
	}

	if (show_symbols) {
		printf("%-40s %-18s %s\n", "Name", "Address", "Offset");
		printf("%-40s %-18s %s\n", "----", "-------", "------");

		for (size_t i = 0; i < symcount; ++i) {
			Elf64_Sym *s = (Elf64_Sym*)((char*)symtab + i * syment);
			unsigned char type = ELF64_ST_TYPE(s->st_info);
			if (type != STT_FUNC) continue;
			const char *name = strtab + s->st_name;
			if (!name || name[0] == '\0') continue;
			uintptr_t val = s->st_value;
			uintptr_t addr_val;
			if (val >= b && val < e) addr_val = val;
			else addr_val = b + val;
			printf("%-40s 0x%016lx 0x%08lx\n", name, (unsigned long)addr_val, (unsigned long)(addr_val - b));
		}
	} else {
		FILE *out = fopen("vdso.so", "wb");
		if (!out) {
			perror("fopen(vdso.so)");
			return 1;
		}
		size_t wrote = fwrite(base, 1, vdso_size, out);
		if (wrote != vdso_size) {
			perror("fwrite(vdso.so)");
			fclose(out);
			return 1;
		}
		fclose(out);
		printf("wrote vdso.so (%zu bytes)\n", vdso_size);
	}

	return 0;
}