/*
 * @(#)ldapprofile
 *
 * Generate /etc/ldap.conf from profile information stored
 * in directory.
 *
 * Copyright (c) 2001 PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Please see COPYING for license terms.
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/param.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>

#ifdef HAVE_LBER_H
#include <lber.h>
#endif
#ifdef HAVE_LDAP_H
#include <ldap.h>
#endif
#ifdef HAVE_LDAP_SSL_H
#include <ldap_ssl.h>
#endif

#ifndef HAVE_LDAP_MEMFREE
#define ldap_memfree(x) free(x)
#endif

#ifndef LDAP_VERSION3
#define LDAP_VERSION3 3
#endif

typedef enum _ProfileSyntax
{
  ProfileSyntaxBoolean,
  ProfileSyntaxInteger,
  ProfileSyntaxString,
  ProfileSyntaxScope
}
ProfileSyntax;

static void usage (int argc, char **argv);
static int getBaseForNisDomain (LDAP * ld, const char *nisDomain,
				char **baseForProfile);
static int connectToServer (char *host, LDAP ** ld);
static char *getStringValue (LDAP * ld, LDAPMessage * entry,
			     const char *attribute);
static char **getStringValues (LDAP * ld, LDAPMessage * entry,
			       const char *attribute);
static int emitDUAConfigProfile (LDAP * ld, const char *base,
				 const char *profile, const char *host,
				 FILE * fp);
static void emitConfigurationHeader (LDAP * ld, LDAPMessage * e, FILE * fp);
static void emitRegenerationInfo (LDAP * ld, const char *, const char *,
				  const char *, FILE * fp);
static void emitConfKey_BASE (LDAP * ld, LDAPMessage * e,
			      const char *defaultBase, FILE * fp);
static void emitConfKey_HOST (LDAP * ld, LDAPMessage * e,
			      const char *defaultHost, FILE * fp);
static void emitConfKey_XXX (LDAP * ld, LDAPMessage * e,
			     const char *attribute, const char *key,
			     ProfileSyntax syn, FILE * fp);
static void emitConfKey_NSS_BASE_XXX (LDAP * ld, LDAPMessage * e, FILE * fp);
static int isValidNSSService (const char *serviceName);
static char *chaseReferral (LDAP * ld, const char *service, char *referral);

static int debug = 0;

int
main (int argc, char **argv)
{
  int c;
  extern char *optarg;
  char *ldapServer = NULL, *profileBase = NULL;
  char *profileName = NULL, *nisDomain = NULL;
  LDAP *ld;
  int rc;

  while ((c = getopt (argc, argv, "h:d:p:b:D")) != -1)
    {
      switch (c)
	{
	case 'h':
	  ldapServer = strdup (optarg);
	  break;
	case 'b':
	  profileBase = strdup (optarg);
	  break;
	case 'p':
	  profileName = strdup (optarg);
	  break;
	case 'd':
	  nisDomain = strdup (optarg);
	  break;
	case 'D':
	  debug++;
	  break;
	default:
	  usage (argc, argv);
	  break;
	}
    }

  if (ldapServer == NULL)
    {
      usage (argc, argv);
    }

  if (profileBase == NULL && nisDomain == NULL)
    {
      usage (argc, argv);
    }

  rc = connectToServer (ldapServer, &ld);
  if (rc != LDAP_SUCCESS)
    {
      int plural = (strchr (ldapServer, ' ') != NULL);
      fprintf (stderr, "%s: could not connect to server%s \"%s\"\n",
	       argv[0], plural ? "s" : "", ldapServer);
      exit (rc);
    }

  if (nisDomain != NULL)
    {
      char *base;

      rc = getBaseForNisDomain (ld, nisDomain, &base);
      if (rc != LDAP_SUCCESS)
	{
	  fprintf (stderr,
		   "%s: Could not locate search base for NIS domain \"%s\"\n",
		   argv[0], nisDomain);
	  exit (rc);
	}

      /* xxx should normalize DNs */
      if (profileBase != NULL)
	{
	  if (strcasecmp (profileBase, base) != 0)
	    {
	      rc = LDAP_NO_SUCH_OBJECT;
	      fprintf (stderr,
		       "%s: NIS domain \"%s\" does not match base \"%s\"\n",
		       argv[0], nisDomain, profileBase);
	      exit (rc);
	    }
	}
      else
	{
	  profileBase = strdup (base);
	}

      ldap_memfree (base);
    }

  rc =
    emitDUAConfigProfile (ld, profileBase, profileName, ldapServer, stdout);
  if (rc != LDAP_SUCCESS)
    {
      if (profileName != NULL)
	{
	  fprintf (stderr,
		   "%s: Could not retrieve DUA configuration profile \"%s\" at \"%s\"\n",
		   argv[0], profileName, profileBase);
	}
      else
	{
	  fprintf (stderr,
		   "%s: Could not retrieve DUA configuration profile at \"%s\"\n",
		   argv[0], profileBase);
	}
      exit (rc);
    }

  ldap_unbind (ld);

  free (ldapServer);
  free (profileBase);

  if (nisDomain != NULL)
    {
      free (nisDomain);
    }

  if (profileName != NULL)
    {
      free (profileName);
    }

  exit (0);
  return 0;
}

static void
usage (int argc, char **argv)
{
  fprintf (stderr,
	   "%s: Usage: ldapprofile [-h ldapServer] [-b profileBase] [-p profileName] [-d nisDomain]\n",
	   argv[0]);
  exit (1);
}

static int
connectToServer (char *host, LDAP ** ld)
{
  int rc, val;

#ifdef HAVE_LDAP_INIT
  *ld = ldap_init (host, LDAP_PORT);
#else
  *ld = ldap_open (host, LDAP_PORT);
#endif
  if (*ld == NULL)
    {
      return LDAP_CONNECT_ERROR;
    }

  val = LDAP_VERSION3;

#ifdef LDAP_OPT_PROTOCOL_VERSION
  rc = ldap_set_option (*ld, LDAP_OPT_PROTOCOL_VERSION, &val);
  if (rc != LDAP_SUCCESS)
    {
      ldap_perror (*ld, "ldap_set_option(LDAP_OPT_SIZELIMIT)");
      return rc;
    }
#else
  (*ld)->ld_version = val;
  rc = LDAP_SUCCESS;
#endif

  val = 1;

#ifdef LDAP_OPT_SIZELIMIT
  rc = ldap_set_option (*ld, LDAP_OPT_SIZELIMIT, &val);
  if (rc != LDAP_SUCCESS)
    {
      ldap_perror (*ld, "ldap_set_option(LDAP_OPT_SIZELIMIT)");
      return rc;
    }
#else
  (*ld)->ld_sizelimit = val;
  rc = LDAP_SUCCESS;
#endif

  return rc;
}

static int
emitDUAConfigProfile (LDAP * ld, const char *base, const char *profileName,
		      const char *hostWithProfile, FILE * fp)
{
  int rc;
#if 1
  char *profileAttrs[] = { "*", "+", NULL };
#else
  char *profileAttrs[] = { "cn",
    "defaultServerList", "preferredServerList",
    "defaultSearchBase", "defaultSearchScope",
    "searchTimeLimit", "bindTimeLimit",
    "credentialLevel", "authenticationMethod",
    "followReferrals", "serviceSearchDescriptor",
    "objectclassMap", "attributeMap",
    "profileTTL", NULL
  };
#endif
  LDAPMessage *profileRes, *profileEntry;
  char filter[LDAP_FILT_MAXSIZ];

  if (profileName == NULL)
    {
      snprintf (filter, sizeof (filter), "(objectclass=DUAConfigProfile)");
    }
  else
    {
      snprintf (filter, sizeof (filter),
		"(&(objectclass=DUAConfigProfile)(cn=%s))", profileName);
    }

  if (debug)
    {
      fprintf (stderr, "DEBUG: subtree search of \"%s\" for \"%s\"\n", base,
	       filter);
    }

  rc =
    ldap_search_s (ld, base, LDAP_SCOPE_SUBTREE, filter, profileAttrs, 0,
		   &profileRes);
  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED)
    {
      ldap_perror (ld, "ldap_search_s");
      return rc;
    }

  profileEntry = ldap_first_entry (ld, profileRes);
  if (profileEntry == NULL)
    {
      ldap_perror (ld, "ldap_first_entry");
      ldap_msgfree (profileRes);
      return LDAP_NO_SUCH_OBJECT;
    }

  fprintf (fp,
	   "######################################################################\n");
  emitConfigurationHeader (ld, profileEntry, fp);
  emitRegenerationInfo (ld, base, profileName, hostWithProfile, fp);
  fprintf (fp,
	   "######################################################################\n\n");

  emitConfKey_HOST (ld, profileEntry, hostWithProfile, fp);
  emitConfKey_BASE (ld, profileEntry, base, fp);
  emitConfKey_XXX (ld, profileEntry, "defaultSearchScope", "SCOPE",
		   ProfileSyntaxScope, fp);
  emitConfKey_XXX (ld, profileEntry, "searchTimeLimit", "TIMELIMIT",
		   ProfileSyntaxInteger, fp);
  emitConfKey_XXX (ld, profileEntry, "bindTimeLimit", "BIND_TIMELIMIT",
		   ProfileSyntaxInteger, fp);
  emitConfKey_XXX (ld, profileEntry, "followReferrals", "REFERRALS",
		   ProfileSyntaxBoolean, fp);
  emitConfKey_NSS_BASE_XXX (ld, profileEntry, fp);

  ldap_msgfree (profileRes);

  return LDAP_SUCCESS;
}

static int
getBaseForNisDomain (LDAP * ld, const char *nisDomain, char **baseForProfile)
{
  int rc;
  char *rootDSEAttrs[] = { "namingContexts", "subschemaSubentry", NULL };
  LDAPMessage *rootDSERes, *rootDSEEntry;
  char **contexts, **schemaContexts, **p;

  if (debug)
    {
      fprintf (stderr, "DEBUG: reading root DSE\n");
    }

  rc =
    ldap_search_s (ld, "", LDAP_SCOPE_BASE, "(objectclass=*)", rootDSEAttrs,
		   0, &rootDSERes);
  if (rc != LDAP_SUCCESS)
    {
      ldap_perror (ld, "ldap_search_s");
      return rc;
    }

  rootDSEEntry = ldap_first_entry (ld, rootDSERes);
  if (rootDSEEntry == NULL)
    {
      ldap_perror (ld, "ldap_first_entry");
      ldap_msgfree (rootDSERes);
      return LDAP_NO_SUCH_OBJECT;
    }

  contexts = getStringValues (ld, rootDSEEntry, "namingContexts");
  if (contexts == NULL)
    {
      ldap_perror (ld, "ldap_get_values");
      ldap_msgfree (rootDSERes);
      return LDAP_NO_SUCH_ATTRIBUTE;
    }

  schemaContexts = getStringValues (ld, rootDSEEntry, "subschemaSubentry");

  *baseForProfile = NULL;

  for (p = contexts; *p != NULL; p++)
    {
      char **q;
      int isUserContext = 1;

      if (debug)
	{
	  fprintf (stderr, "DEBUG: got naming context \"%s\"\n", *p);
	}

      if (schemaContexts != NULL)
	{
	  for (q = schemaContexts; *q != NULL; q++)
	    {
	      if (strcasecmp (*p, *q) == 0)
		{
		  isUserContext = 0;
		  break;
		}
	    }
	}

      if (isUserContext)
	{
	  LDAPMessage *baseRes, *baseEntry;
#if 1
	  char *baseAttrs[] = { "*", "+", NULL };
#else
	  char *baseAttrs[] = { "nisDomain", NULL };
#endif
	  char nisDomainFilter[LDAP_FILT_MAXSIZ];

	  snprintf (nisDomainFilter, sizeof (nisDomainFilter),
		    "(nisDomain=%s)", nisDomain);

	  if (debug)
	    {
	      fprintf (stderr, "DEBUG: subtree search of \"%s\" for \"%s\"\n",
		       *p, nisDomainFilter);
	    }

	  rc =
	    ldap_search_s (ld, *p, LDAP_SCOPE_SUBTREE, nisDomainFilter,
			   baseAttrs, 0, &baseRes);
	  if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED)
	    {
	      continue;
	    }

	  baseEntry = ldap_first_entry (ld, baseRes);
	  if (baseEntry == NULL)
	    {
	      ldap_msgfree (baseRes);
	      continue;
	    }

	  *baseForProfile = ldap_get_dn (ld, baseEntry);

	  ldap_msgfree (baseRes);

	  if (*baseForProfile != NULL)
	    {
	      break;
	    }

	}
    }

  ldap_value_free (contexts);
  if (schemaContexts != NULL)
    {
      ldap_value_free (schemaContexts);
    }
  ldap_msgfree (rootDSERes);

  if (*baseForProfile == NULL)
    {
      rc = LDAP_NO_SUCH_OBJECT;
    }
  else
    {
      rc = LDAP_SUCCESS;
    }

  return rc;
}

static char *
getStringValue (LDAP * ld, LDAPMessage * entry, const char *attribute)
{
  char **values;
  char *value;

  values = ldap_get_values (ld, entry, (char *) attribute);
  if (values == NULL)
    {
      return NULL;
    }

  value = strdup (values[0]);
  ldap_value_free (values);
  return value;
}

static char **
getStringValues (LDAP * ld, LDAPMessage * entry, const char *attribute)
{
  return ldap_get_values (ld, entry, (char *) attribute);
}

static void
emitRegenerationInfo (LDAP * ld, const char *base, const char *profileName,
		      const char *hostWithProfile, FILE * fp)
{
  /*
   * We provide a Perl script that uses this information
   * to re-run ldapprofile at boot time.
   */
  fprintf (fp, "# Profile base: %s\n", base);
  if (profileName != NULL)
    {
      fprintf (fp, "# Profile name: %s\n", profileName);
    }
  fprintf (fp, "# Profile host: %s\n", hostWithProfile);
}

static void
emitConfigurationHeader (LDAP * ld, LDAPMessage * e, FILE * fp)
{
  time_t t;
  char *creationTime, *expiryVal, *expiryTime, *dn;

  t = time (NULL);
  creationTime = strdup (ctime (&t));

  expiryTime = NULL;

  expiryVal = getStringValue (ld, e, "profileTTL");
  if (expiryVal != NULL)
    {
      t += atoi (expiryVal);
      free (expiryVal);
      expiryTime = strdup (ctime (&t));
    }

  dn = ldap_get_dn (ld, e);

  fprintf (fp, "# @(#)ldap.conf generated by ldapprofile\n");
  fprintf (fp, "#\n");
  fprintf (fp, "# Created at: %s", creationTime);
  if (expiryTime != NULL)
    {
      fprintf (fp, "# Valid until: %s", expiryTime);
    }
  if (dn != NULL)
    {
      fprintf (fp, "# Profile DN: %s\n", dn);
    }

  if (dn != NULL)
    {
      ldap_memfree (dn);
    }

  free (creationTime);
  if (expiryTime != NULL)
    {
      free (expiryTime);
    }
}

static void
emitConfKey_HOST (LDAP * ld, LDAPMessage * e, const char *defaultHost,
		  FILE * fp)
{
  char *defaultServerList, *preferredServerList;

  defaultServerList = getStringValue (ld, e, "defaultServerList");
  preferredServerList = getStringValue (ld, e, "preferredServerList");

  fprintf (fp, "HOST ");

  if (preferredServerList != NULL)
    {
      fprintf (fp, "%s", preferredServerList);
    }

  if (defaultServerList != NULL)
    {
      fprintf (fp, "%s%s", (preferredServerList != NULL ? " " : ""),
	       defaultServerList);
    }

  if (preferredServerList == NULL && defaultServerList == NULL)
    {
      fprintf (fp, "%s", defaultHost);
    }

  fprintf (fp, "\n");

  if (preferredServerList != NULL)
    {
      free (preferredServerList);
    }

  if (defaultServerList != NULL)
    {
      free (defaultServerList);
    }
}

static void
emitConfKey_BASE (LDAP * ld, LDAPMessage * e, const char *baseOfProfile,
		  FILE * fp)
{
  char *defaultSearchBase;

  fprintf (fp, "BASE ");

  defaultSearchBase = getStringValue (ld, e, "defaultSearchBase");
  if (defaultSearchBase != NULL)
    {
      fprintf (fp, "%s\n", defaultSearchBase);
      free (defaultSearchBase);
    }
  else
    {
      fprintf (fp, "%s\n", baseOfProfile);
    }
}

static void
emitConfKey_XXX (LDAP * ld, LDAPMessage * e, const char *attribute,
		 const char *key, ProfileSyntax syn, FILE * fp)
{
  char *value;
  char *c;

  value = getStringValue (ld, e, attribute);
  if (value != NULL)
    {
      switch (syn)
	{
	case ProfileSyntaxBoolean:
	  if (strcasecmp (value, "TRUE") && strcasecmp (value, "FALSE"))
	    {
	      fprintf (stderr,
		       "warning: malformed boolean profile value %s: %s\n",
		       attribute, value);
	    }
	case ProfileSyntaxInteger:
	  for (c = value; *c != '\0'; c++)
	    {
	      if (!isdigit (*c))
		{
		  fprintf (stderr,
			   "warning: malformed integer profile value %s: %s\n",
			   attribute, value);
		  break;
		}
	    }
	  break;
	case ProfileSyntaxScope:
	  if (strcmp (value, "base") &&
	      strcmp (value, "one") && strcmp (value, "sub"))
	    {
	      fprintf (stderr,
		       "warning: malformed scopeSyntax profile value %s: %s\n",
		       attribute, value);
	    }
	  break;
	case ProfileSyntaxString:
	default:
	  break;
	}
      fprintf (fp, "%s %s\n", key, value);
      free (value);
    }
}

static int
isValidNSSService (const char *serviceName)
{
  static char *validNSSServices[] = { "passwd",
    "shadow",
    "group",
    "hosts",
    "services",
    "networks",
    "protocols",
    "rpc",
    "ethers",
    "netmasks",
    "bootparams",
    "aliases",
    "netgroup",
    NULL
  };
  char **p;

  for (p = validNSSServices; *p != NULL; p++)
    {
      if (strcmp (*p, serviceName) == 0)
	{
	  return 1;
	}
    }

  return 0;
}

static char *
chaseReferral (LDAP * ld, const char *service, char *referral)
{
  LDAPMessage *res, *e;
  int rc;
  const char *base = referral + sizeof ("ref:") - 1;
#if 1
  char *searchDescAttrs[] = { "*", "+", NULL };
#else
  char *searchDescAttrs[] = { "serviceSearchDescriptor", NULL };
#endif
  char **descriptors, **p;

  if (debug)
    {
      fprintf (stderr, "DEBUG: chasing referral \"%s\"\n", referral);
    }

  rc =
    ldap_search_s (ld, base, LDAP_SCOPE_BASE,
		   "(objectclass=DUAConfigProfile)", searchDescAttrs, 0,
		   &res);
  if (rc != LDAP_SUCCESS)
    {
      ldap_perror (ld, "ldap_search_s");
      return NULL;
    }

  e = ldap_first_entry (ld, res);
  if (e == NULL)
    {
      ldap_perror (ld, "ldap_first_entry");
      ldap_msgfree (res);
      return NULL;
    }

  descriptors = getStringValues (ld, e, "serviceSearchDescriptor");
  if (descriptors == NULL)
    {
      fprintf (stderr,
	       "warning: profile \"%s\" has no descriptor for service \"%s\"\n",
	       base, service);
      ldap_msgfree (res);
      return NULL;
    }

  for (p = descriptors; *p != NULL; p++)
    {
      char *referredService, *referredBase;

      referredService = *p;
      referredBase = strchr (referredService, ':');
      if (referredBase == NULL)
	{
	  fprintf (stderr,
		   "warning: malformed serviceSearchSyntax value serviceSearchDescriptor: %s\n",
		   *p);
	  continue;
	}

      *referredBase = '\0';
      referredBase++;

      if (!strcmp (referredService, service))
	{
	  const char *result = strdup (referredBase);

	  ldap_value_free (descriptors);
	  ldap_msgfree (res);

	  return strdup (result);
	}
    }

  fprintf (stderr,
	   "warning: profile \"%s\" has no descriptor for service \"%s\"\n",
	   base, service);

  ldap_value_free (descriptors);
  ldap_msgfree (res);

  return NULL;
}

static void
emitConfKey_NSS_BASE_XXX (LDAP * ld, LDAPMessage * e, FILE * fp)
{
  char **descriptors;
  char **p;

  descriptors = getStringValues (ld, e, "serviceSearchDescriptor");
  if (descriptors == NULL)
    {
      return;
    }

  for (p = descriptors; *p != NULL; p++)
    {
      char *service, *base, *semicolon;

      service = *p;
      base = strchr (service, ':');
      if (base == NULL)
	{
	  fprintf (stderr,
		   "warning: malformed serviceSearchSyntax value serviceSearchDescriptor: %s\n",
		   *p);
	  continue;
	}
      *base = '\0';
      base++;

      /* Semicolons separate multiple descriptors for a single service. */
      /* We only support one because nss_ldap only supports one, now. */
      /* Do we need to do any escaping because semicolons can occur in */
      /* distinguished names? */
      semicolon = strchr (base, ';');
      if (semicolon != NULL)
	*semicolon = '\0';

      if (isValidNSSService (service))
	{
	  int depth = 0;
	  char *chasedBase = strdup (base);
	  char *c;

	  while ((strncmp (chasedBase, "ref:", 4) == 0) && ++depth < 4)
	    {
	      char *oldChasedBase = chasedBase;

	      chasedBase = chaseReferral (ld, service, oldChasedBase);
	      if (chasedBase == NULL)
		{
		  fprintf (stderr,
			   "warning: could not follow serviceSearchDescriptor referral \"%s\"\n",
			   oldChasedBase);
		  break;
		}
	      free (oldChasedBase);
	    }

	  if (chasedBase != NULL)
	    {
	      for (c = service; *c != '\0'; c++)
		{
		  *c = toupper (*c);
		}

	      fprintf (fp, "NSS_BASE_%s %s\n", service, chasedBase);

	      free (chasedBase);
	    }
	}
    }

  ldap_value_free (descriptors);
}
