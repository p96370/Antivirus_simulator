#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define NMAX 10000

// malware sau phishing
int check_database(char *s)
{
	FILE *data = fopen("data/urls/domains_database", "rt");
	while (!feof(data)) {
		char line[NMAX];
		fscanf(data, "%s", line);
		if (strstr(s, line))
			return 1; // is malicious from database
	}
	fclose(data);
	return 0; // cannot be found int the database
}

// checks if the URL is executable
int check_malware(char *s)
{
	int len = strlen(s);
	if (s[len - 1] == 'e' && s[len - 2] == 'x' && s[len - 3] == 'e' &&
		s[len - 4] == '.')
		return 1;
	if (strstr(s, ".exe"))
		return 1; // is malware
	// return 0 if it's not malware
	return 0;
}

// checks if the domain contains more than 10% digits
int check_digits(char *s)
{
	int len = strlen(s), digits = 0, len_dom = 0;
	int i = 0;
	//checks if the domain starts either with http or https or neither
	char *p = strstr(s, "http://");
	if (p) {
		i = 7;
	} else {
		p = strstr(s, "https://");
		if (p)
			i = 8;
	}
	while (s[i] != '/' && i < len) {
		if (s[i] >= '0' && s[i] <= '9')
			digits++;
		i++;
		len_dom++;
	}
	if (digits * 10 >= len_dom)
		return 1; // is malware or phishing
	return 0;
}

// checks if contains www in a normal format
int check_www(char *s)
{
	int poz = 0;
	char *p = strstr(s, "http://");
	if (p)
		poz = 7;
	p = strstr(s, "https://");
	if (p)
		poz = 8;
	if (s[poz] == 'w' && s[poz + 1] == 'w' && s[poz + 2] == 'w') {
		if (s[poz + 3] != '.')
			return 1;
	}
	return 0;
}

//checks if duration is longer than 1 sec
int valid_flow_time(char *s)
{
	char *p = strstr(s, "0 days");
	if (p) {
		for (int i = 7; i <= 14; i++)
			if (p[i] != ':' && p[i] != '0')
				return 0;
	}
	return 1; // e 0 sec
}

// checks if the line end with .0.0, which means it's valid
int valid_flow_pkts(char *s)
{
	int len = strlen(s);
	if (s[len - 1] == '0' && s[len - 2] == '.' && s[len - 3] == '0' &&
		s[len - 4] == ',')
		return 1; // e ,0.0
	return 0;
}

int main(void)
{
	// TASK 1
	FILE *f = fopen("data/urls/urls.in", "rt");
	FILE *g = fopen("urls-predictions.out", "wt");

	char *s = (char *)malloc(NMAX * sizeof(char));
	int nr = 0;
	while (!feof(f)) {
		fscanf(f, "%s\n", s);
		nr++;
		int ok1 = check_database(s);
		int ok2 = check_malware(s);
		int ok3 = check_digits(s);
		if (ok1 || ok2 || ok3) {
			fprintf(g, "1\n");
		} else {
			if (check_www(s))
				fprintf(g, "1\n");
			else
				fprintf(g, "0\n");
		}
	}
	free(s);
	fclose(f);
	fclose(g);

	// TASK 2

	FILE *in = fopen("data/traffic/traffic.in", "rt");
	FILE *out = fopen("traffic-predictions.out", "wt");

	char *sir = (char *)malloc(NMAX * sizeof(char));
	fgets(sir, NMAX, in);
	while (fgets(sir, NMAX, in)) {
		if (strchr(sir, '\n'))
			sir[strlen(sir) - 1] = '\0';
		if (valid_flow_time(sir)) {
			fprintf(out, "0\n");
		} else {
			if (valid_flow_pkts(sir))
				fprintf(out, "0\n");
			else
				fprintf(out, "1\n");
		}
	}
	free(sir);
	fclose(in);
	fclose(out);

	return 0;
}
