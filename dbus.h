#ifndef MCED_DBUS_COMMON_H__
#define MCED_DBUS_COMMON_H__

#include <dbus/dbus.h>

/* The well-known name for this service. */
#define DBUS_SERVICE_NAME		"org.mcedaemon.MachineCheckDaemon"

/* The object path to the instance. */
#define DBUS_SERVICE_OBJECT_PATH	"/org/mcedaemon/MachineCheckNotifier"

/* The object interface. This must match the XML. */
#define DBUS_SERVICE_INTERFACE		"org.mcedaemon.MachineCheckNotifier"

/* The name of an MCE signal. */
#define DBUS_SIGNAL_NAME_MCE		"machine_check"

/* Initialize DBUS. */
int dbus_init(int which_bus);

/* Send a single MCE over DBUS */
struct mce;
void dbus_send_mce(struct mce *mce);

#endif /* MCED_DBUS_COMMON_H__ */
