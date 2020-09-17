/** NexusOS: Python interface to trustworthy system services */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <Python.h>

#include <nexus/test.h>
#include <nexus/types.h>
#include <nexus/rdtsc.h>
#include <nexus/nexuscalls.h>
#include <nexus/syscall-defs.h>
#include <nexus/Thread.interface.h>

#define CPUINFO_FILE "/proc/cpuinfo"
#define OSINFO_FILE "/proc/version"
#define BUF_SIZE 512


////////  support functions

static PyObject *
PyError(const char *msg)
{
	PyErr_SetString(PyExc_TypeError, msg);
	return Py_BuildValue("s", NULL);
}

/** Return the timestamp counter. 
	As double, because Py_BuildValue does not seem to support 'long long' */
static PyObject *
nexus_tsc(PyObject *self, PyObject *args)
{
	return Py_BuildValue("d", (double) rdtsc64());
}


/** Lookup resource string -> ipc port of authoritative server */
static int
__nexus_demux_resource(const char *resource)
{
fprintf(stderr, "NXDEBUG: demux [%s]\n", resource);
	// lookup resource name -> controlling server (ipc port)
	if (!strcmp(resource, "cpu"))
		return resctl_cpu_port;
	else
                return -1;
}

static char *
__nexus_readcert(const char *filepath)
{
        struct stat stat;
        char *data;
        int fd; 

        // open certificate
        fd = open(filepath, O_RDONLY);
        if (fd < 0)
                ReturnError(NULL, "cannot open certificate");

        if (fstat(fd, &stat))
                ReturnError(NULL, "cannot stat certificate");

        // read certificate into memory
        data = malloc(stat.st_size);
        if (read(fd, data, stat.st_size) != stat.st_size)
                ReturnError(NULL, "cannot read certificate");

        if (close(fd))
                ReturnError(NULL, "error at close certificate");

        return data;
}

////////  module callables

static PyObject *
nexus_fcntl(PyObject *self, PyObject *args)
{
	long cmd, arg;
	int fd, ret;

	if (!PyArg_ParseTuple(args, "ill", &fd, &cmd, &arg)) {
		PyErr_SetString(PyExc_TypeError, "incorrect arguments");
		return NULL;
	}

	ret = fcntl(fd, cmd, arg);
	
	return Py_BuildValue("i", ret);
}

/** Execute a command. Poor replacement for subprocess (until that works)
    NB: cannot call this nexus.exec(), because exec is a reserved keyword. */
static PyObject *
nexus_run(PyObject *self, PyObject *args)
{
	const char *command;
	int pid;

	if (!PyArg_ParseTuple(args, "s", &command)) 
	        return PyError("incorrect arguments");

        if (!command || strlen(command) == 0)
	        return PyError("no argument");

	pid = nxcall_exec(command);
	return Py_BuildValue("i", pid);
}

static PyObject *
nexus_programhash(PyObject *self, PyObject *args)
{
	PyObject *ret;
        char filepath[128];
        char *data;

        // generate certificate
        if (Thread_Sha1_GetCert(0, filepath))
                return PyError("Error in certificate generation");

        data = __nexus_readcert(filepath);
        if (!data)
		return PyError("Error at ReadCert");
                
        ret = Py_BuildValue("s", data);
	free(data);
	
        return ret;
}

/** Reserve a resource share:
    resource_reserve(char * resource, int pid, int quantity) 
 
    Throws an OverflowError if not enough free resources are available 
    to fulfill the request */
static PyObject *
nexus_resource_reserve(PyObject *self, PyObject *args)
{
	char *resource;
	int process, account, quantity, ret, port;

	// parse input
	if (!PyArg_ParseTuple(args, "sdd", &resource, &process, &quantity)) 
		return PyError("incorrect arguments");

        port = __nexus_demux_resource(resource);
	if (port < 0)	
                return PyError("unknown resource");

	// lookup (or create) the process's account
	account = Resource_Account_ByProcess_ext(port, process);
	if (account < 0) {
		account = Resource_Account_New_ext(port);
		if (Resource_Account_AddProcess_ext(port, account, process))
			return PyError("Error at AddProcess");
	}

	// (try to) add resources to account
	if (Resource_Account_AddResource_ext(port, quantity, account)) {
		PyErr_SetString(PyExc_OverflowError, "Insufficient Resources");
		return Py_BuildValue("s", NULL);
	}

	return Py_BuildValue("i", ret);	
}

/** Attest to the resource share of an account:
    resource_attest(char *resource, int process) */
static PyObject *
nexus_resource_attest(PyObject *self, PyObject *args)
{
        PyObject *ret;
	char *resource, *static_filepath, *data;
	int fd, port, process, account, quantity;

	// parse input
	if (!PyArg_ParseTuple(args, "si", &resource, &process)) 
	        return PyError("incorrect arguments");

        port = __nexus_demux_resource(resource);
	if (port < 0)	
                return PyError("unknown resource");

        // get account
	account = Resource_Account_ByProcess_ext(port, process);
	
        // call
        // XXX replace static filename with randomly generated
        static_filepath = "/tmp/pycert";
	if (Resource_Account_Attest_ext(port, account, static_filepath))
		return PyError("Error at Attest");

        // read
        data = __nexus_readcert(static_filepath);
        if (!data)
                return PyError("Error at Read Cert");

	ret = Py_BuildValue("s", data);	
        free(data);

        unlink(static_filepath);
        return ret;
}

/** Return resource control information:
    resctl_size(const char *resource, int pid)

    @param pid is a process id or -1 for total size */
static PyObject *
nexus_resource_size(PyObject *self, PyObject *args)
{
        char *resource;
        int ret, port, process, account;

        fprintf(stderr, "NXDEBUG: RESOURCE_SIZE...\n");
	// parse input
	if (!PyArg_ParseTuple(args, "si", &resource, &process)) 
	        return PyError("incorrect arguments");
        fprintf(stderr, "NXDEBUG: IN: resource %s, process %d\n", resource, process);

        // lookup server port
        port = __nexus_demux_resource(resource);
	if (port < 0)	
                return PyError("unknown resource");

        // call
        if (process < 1)
                ret = Resource_Info_SizeTotal_ext(port);
        else
                ret = Resource_Info_SizeAccount_ext(port, process);

        fprintf(stderr, "NXDEBUG: resource %d -> size %d\n", process, ret);
        return Py_BuildValue("i", ret);
}

/** Embedded code, so that it becomes part of the process SHA1 
    and cannot be overwritten by malicious .py code */
const char fingerprint_internal[] = "					\
import sys\n								\
import inspect\n							\
import hashlib\n							\
\n									\
def hashprint():\n							\
    # create table of { modulename : sha1 } elements\n			\
    hashtable = {}\n							\
    for key, value in sys.modules.items():\n				\
        try:\n								\
            source = inspect.getfile(value)\n				\
    	    fd = open(source)\n						\
    	    data = fd.read()\n						\
    	    fd.close()\n						\
            hashtable[key] = hashlib.sha1(data)\n			\
        except TypeError:\n						\
            # builtin: no need to hash: part of python binary hash\n	\
            pass\n							\
\n									\
    # turn dictionary into a string of name=hash pairs\n		\
    prettylist = []\n							\
    keys = hashtable.keys()\n						\
    keys.sort()\n							\
    for key in keys:\n							\
        prettylist.append('%s=%s' % (key, hashtable[key].hexdigest()))\n\
    prettystring = ' and '.join(prettylist)\n				\
\n									\
    # prepend activecode element\n					\
    code = hashlib.sha1(prettystring).hexdigest()\n			\
    return 'activecode=%s %s' % (code, prettystring)\n			\
";

/** Generate a fingerprint */
static PyObject *
nexus_shared_state(PyObject *self, PyObject *args)
{
	PyObject *fingerprint, *dict;

	dict = PyDict_New();

	// load the embedded 'module'
	PyRun_String(fingerprint_internal, Py_file_input, dict, dict);

	// get fingerprint string by running fingerprint.hashstring()
	fingerprint = PyRun_String("hashprint()", Py_eval_input, dict, dict);
	if (!fingerprint)
		return PyError("fingerprint generation error");

	// cleanup
	Py_DECREF(dict);
	return fingerprint;
}

/** Generate a fingerprint and wrap it in a certificate or label */
static PyObject *
nexus_shared_state_too(PyObject *self, PyObject *args, int do_cert)
{
	PyObject *fingerprint, *retobj;
	struct stat stat;
	char filepath[128], *fpstring, *retstring, *statements[2];
	int ret, fd;

	// get fingerprint string
	fingerprint = nexus_shared_state(self, args);
	if (!PyArg_Parse(fingerprint, "s", &fpstring))
		return PyError("fingerprint extraction error");
	Py_DECREF(fingerprint);

	// call file generation function
	statements[0] = fpstring;
	statements[1] = NULL;
	if (do_cert)
		ret = Thread_Sha1_SaysCert(statements, filepath);
	else
		ret = Thread_Sha1_Says(statements, filepath);
	if (ret)
		return PyError("file extraction error");

	// read file contents 
	fd = open(filepath, O_RDONLY);
	if (fd < 0 || fstat(fd, &stat))
		return PyError("file open error");
	retstring = malloc(stat.st_size);
	if (read(fd, retstring, stat.st_size) != stat.st_size)
		return PyError("file read error");
	close(fd);

	// convert and return
	retobj = Py_BuildValue("s", retstring);
	free(retstring);
	return retobj;
}		

static PyObject *
nexus_label_state(PyObject *self, PyObject *args)
{
	return nexus_shared_state_too(self, args, 0);
}

static PyObject *
nexus_cert_state(PyObject *self, PyObject *args)
{
	return nexus_shared_state_too(self, args, 1);
}

static PyObject *
nexus_shared_says(PyObject *self, PyObject *args, int do_cert)
{
	const char *statement;
	char *statements[2], mystatement[256], filepath[128];
	int ret;

	// read statement S
	if (!PyArg_ParseTuple(args, "s", &statement)) {
	  PyErr_SetString(PyExc_TypeError, "incorrect arguments");
	  return NULL;
	}

	// change to 'python.code says S'
	if (snprintf(mystatement, 255, 
			"process.%d.code says %s", 
			getpid(), statement) == 255)
		return Py_BuildValue("s", NULL);

	// generate statement
	statements[0] = mystatement;
	statements[1] = NULL;
	if (do_cert)
		ret = Thread_Sha1_SaysCert(statements, filepath);
	else
		ret = Thread_Sha1_Says(statements, filepath);

	// return filepath
	if (ret)
		return Py_BuildValue("s", NULL);
	else
		return Py_BuildValue("s", filepath);
}

static PyObject *
nexus_label_says(PyObject *self, PyObject *args)
{
	return nexus_shared_says(self, args, 0);
}

static PyObject *
nexus_cert_says(PyObject *self, PyObject *args)
{
	return nexus_shared_says(self, args, 1);
}

static PyMethodDef NexusMethods[] = {
	{"tsc", nexus_tsc, METH_VARARGS,
	 	"Return the 64 Pentium timestamp counter (TSC)"},
	{"run", nexus_run, METH_VARARGS,
	 	"Execute a command (similar to the system call in libc)"},
	{"fcntl", nexus_fcntl, METH_VARARGS,
	 	"posix fcntl with support for nexus-specific commands"},
	{"programhash",  nexus_programhash, METH_VARARGS,
	 	"Return hash of a program"},
	{"state", nexus_shared_state, METH_VARARGS, 
	 	"Generate a string that records all state"},
	{"state_label", nexus_label_state, METH_VARARGS, 
	 	"Generate a NAL label ``python says code is <<fingerprint>>''"},
	{"state_cert", nexus_cert_state, METH_VARARGS,
	 	"Generate an X509 cert ``python says code is <<fingerprint>>''"},
	{"says_label", nexus_label_says, METH_VARARGS,
	 	"Generate a NAL label ``code says S''"},
	{"says_cert", nexus_cert_says, METH_VARARGS,
	 	"Generate an X509 cert ``code says S''"},
        {"resource_reserve", nexus_resource_reserve, METH_VARARGS,
                "Reserve a quantity of a resource"},
        {"resource_attest", nexus_resource_reserve, METH_VARARGS,
                "Generate an X509 that attests to a resource reservation"},
        {"resource_size", nexus_resource_size, METH_VARARGS,
                "Return dimension information"},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};

PyMODINIT_FUNC
initnexus(void)
{
	(void) Py_InitModule("nexus", NexusMethods);
}

#if 0
int
main(int argc, char *argv[])
{
	/* Pass argv[0] to the Python interpreter */
	Py_SetProgramName(argv[0]);

	/* Initialize the Python interpreter.  Required. */
	Py_Initialize();

	/* Add a static module */
	initnexus();

	return 0;
}
#endif

/* vim: set ts=8 sw=8: */

