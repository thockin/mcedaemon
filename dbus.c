#include <stdint.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include "mced.h"
#include "dbus.h"
#include "dbus_asv.h"
#include "auto.dbus_server.h"

/*
 * Define the signals that we can generate.
 */
enum signal_type {
	MCED_SIGNAL_MCE = 0,
	MCED_SIGNAL_COUNT
};

/*
 * We need some type definition in order to participate in D-Bus via glib
 * (and GObject and GType), but we don't actually have any instance data.
 *
 * There are all sorts of conventions about naming built into these libs,
 * which is why these names are what they are.
 */
typedef struct {
	GObject parent;				/* the parent object state */
} McedGObject;

typedef struct {
	GObjectClass parent;			/* the parent class state */
	guint signals[MCED_SIGNAL_COUNT];	/* signals for this class */
} McedGObjectClass;

/*
 * It is common to define macros like these for GType implementations.
 */
#define MCED_TYPE_OBJECT	(mced_gobject_get_type())
#define MCED_OBJECT(object) \
	(G_TYPE_CHECK_INSTANCE_CAST((object), MCED_TYPE_OBJECT, McedGObject))
#define MCED_OBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), MCED_TYPE_OBJECT, McedGObjectClass))
#define MCED_IS_OBJECT(object) \
	(G_TYPE_CHECK_INSTANCE_TYPE((object), MCED_TYPE_OBJECT))
#define MCED_IS_OBJECT_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), MCED_TYPE_OBJECT))
#define MCED_OBJECT_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), MCED_TYPE_OBJECT, McedGObjectClass))

/* Define our new type. */
G_DEFINE_TYPE(McedGObject, mced_gobject, G_TYPE_OBJECT)

/*
 * Object initializer
 *
 * Called by G_DEFINE_TYPE-generated code.
 */
static void
mced_gobject_init(McedGObject *obj)
{
	g_assert(obj != NULL);
}

/*
 * Class initializer
 *
 * Creates the signals that we can emit from any object of this class and
 * finally registers the type into the GLib/D-Bus wrapper so that it may
 * add its own magic.
 *
 * Called by G_DEFINE_TYPE-generated code.
 */
static void
mced_gobject_class_init(McedGObjectClass *klass)
{
	g_assert(klass != NULL);

	/* create the signals we intend to emit  */
	klass->signals[MCED_SIGNAL_MCE] = g_signal_new(
	    DBUS_SIGNAL_NAME_MCE,	/* name of the signal */
	    G_OBJECT_CLASS_TYPE(klass),	/* GType this signal is bound to */
	    G_SIGNAL_RUN_LAST,		/* GSignalFlags */
	    0,				/* offset, not used */
	    NULL,			/* accumulator, not used */
	    NULL,			/* accumulator data, not used */
	    g_cclosure_marshal_VOID__POINTER, /* marshal function */
	    G_TYPE_NONE,		/* GType for return value */
	    1,				/* number of GType parameters */
	    dbus_asv_gtype());		/* GType(s) of parameters */

	/* bind this GType into the GLib/D-Bus wrappers */
	dbus_g_object_type_install_info(MCED_TYPE_OBJECT,
	                                &dbus_glib_mced_gobject_object_info);
}

/* The GObject representing our D-Bus connection. */
static DBusGConnection *dbus_connection_instance = NULL;

/* The McedGObject that will serve all requsts. */
static McedGObject *mced_gobject_instance = NULL;

/*
 * Emit a DBUS signal for a single MCE.
 */
void
dbus_send_mce(struct mce *mce)
{
	/* to access the signal ids, we need the class structure first */
	McedGObjectClass *klass = MCED_OBJECT_GET_CLASS(mced_gobject_instance);

	/* convert a 'struct mce' into a 'dbus_asv' */
	dbus_asv *payload = dbus_asv_new(
	    "%c", G_TYPE_UINT,   (uint32_t)mce->cpu,
	    "%S", G_TYPE_INT,    (int32_t)mce->socket,
	    "%p", G_TYPE_UINT,   (uint32_t)mce->init_apic_id,
	    "%v", G_TYPE_INT,    (int32_t)mce->vendor,
	    "%A", G_TYPE_UINT,   (int32_t)mce->cpuid_eax,
	    "%b", G_TYPE_UINT,   (uint32_t)mce->bank,
	    "%s", G_TYPE_UINT64, (uint64_t)mce->mci_status,
	    "%a", G_TYPE_UINT64, (uint64_t)mce->mci_address,
	    "%m", G_TYPE_UINT64, (uint64_t)mce->mci_misc,
	    "%g", G_TYPE_UINT64, (uint64_t)mce->mcg_status,
	    "%G", G_TYPE_UINT,   (uint32_t)mce->mcg_cap,
	    "%t", G_TYPE_UINT64, (uint64_t)mce->time,
	    "%B", G_TYPE_INT,    (int32_t)mce->boot,
	    NULL);

	/* send the signal */
	g_signal_emit(mced_gobject_instance, klass->signals[MCED_SIGNAL_MCE],
	              0, payload);

	/* clean up */
	dbus_asv_destroy(payload);

	/* this is pedantic to avoid runaway memory under very heavy load */
	dbus_g_connection_flush(dbus_connection_instance);
}

int
dbus_init(int which_bus)
{
	DBusGProxy *bus_proxy = NULL;
	guint result;
	GError *error = NULL;

	/* initialize the GType/GObject system */
	g_type_init();

	/* connect to D-Bus */
	mced_log(LOG_INFO, "connecting to dbus\n");
	dbus_connection_instance = dbus_g_bus_get(which_bus, &error);
	if (error != NULL) {
		mced_log(LOG_ERR, "can't connect to dbus: %s\n",
		         error->message);
		return -1;
	}

	mced_debug(1, "DBG: requesting dbus service name %s\n",
	           DBUS_SERVICE_NAME);

	/*
	 * In order to register a well-known name, we need to use the
	 * "RequestMethod" of the /org/freedesktop/DBus interface. Each bus
	 * provides an object that will implement this interface.
	 *
	 * In order to do the call, we need a proxy object first.
	 *     DBUS_SERVICE_DBUS = "org.freedesktop.DBus"
	 *     DBUS_PATH_DBUS = "/org/freedesktop/DBus"
	 *     DBUS_INTERFACE_DBUS = "org.freedesktop.DBus"
	 */
	bus_proxy = dbus_g_proxy_new_for_name(dbus_connection_instance,
	                                      DBUS_SERVICE_DBUS,
	                                      DBUS_PATH_DBUS,
	                                      DBUS_INTERFACE_DBUS);
	if (bus_proxy == NULL) {
		mced_log(LOG_ERR, "can't get dbus proxy\n");
		return -1;
	}

	/*
	 * The RPC call requires two parameters:
	 *      arg0: (D-Bus STRING): name to request
	 *      arg1: (D-Bus UINT32): flags for registration
	 * and will return one uint32 indicating the result of the RPC call.
	 *
	 * See "org.freedesktop.DBus.RequestName" at
	 *  http://dbus.freedesktop.org/doc/dbus-specification.html for more.
	 *
	 * The call will return FALSE if it sets the GError.
	 */
	if (!dbus_g_proxy_call(bus_proxy,
	                       "RequestName",	/* method name */
	                       &error,		/* out-pointer to GError */
	                       G_TYPE_STRING,	/* GType for arg0 */
	                       DBUS_SERVICE_NAME, /* data for arg0 (name) */
	                       G_TYPE_UINT,	/* GType for arg1 */
	                       0,		/* data for arg1 (flags) */
	                       G_TYPE_INVALID,	/* end of args */
	                       G_TYPE_UINT,	/* GType for return value */
	                       &result,		/* out-pointer for return */
	                       G_TYPE_INVALID)) { /* end of return values */
		mced_log(LOG_ERR, "dbus RequestName RPC failed: %s\n",
		         error->message);
		return -1;
	}
	if (result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		mced_log(LOG_ERR, "can't get dbus service name\n");
		return -1;
	}

	/* Create a single instance of our object type. */
	mced_gobject_instance = g_object_new(MCED_TYPE_OBJECT, NULL);
	if (mced_gobject_instance == NULL) {
		mced_log(LOG_ERR, "can't create McedGObject instance\n");
		return -1;
	}

	/* Register it with D-Bus. */
	dbus_g_connection_register_g_object(dbus_connection_instance,
	                                    DBUS_SERVICE_OBJECT_PATH,
	                                    G_OBJECT(mced_gobject_instance));

	/* Done. */
	mced_debug(1, "DBG: dbus is ready\n");

	return 0;
}
