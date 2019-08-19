package edu.uiuc.ncsa.myproxy.oa4mp.server.testing;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalStoreCommands;
import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientSorter;
import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.apache.commons.codec.digest.DigestUtils;

import java.io.FileReader;
import java.util.HashMap;
import java.util.List;

/**
 * Commands for a base client store. This is the super class to several variations of clients.
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/16 at  1:03 PM
 */
public abstract class BaseClientStoreCommands extends StoreCommands2 {
    public BaseClientStoreCommands(MyLoggingFacade logger, String defaultIndent, Store clientStore, ClientApprovalStore clientApprovalStore, PermissionsStore permissionsStore) {
        super(logger, defaultIndent, clientStore);
        this.clientApprovalStore = clientApprovalStore;
        this.permissionsStore = permissionsStore;
        clientApprovalStoreCommands = new ClientApprovalStoreCommands(logger, defaultIndent, clientApprovalStore);
        setSortable(new ClientSorter());
    }

    public BaseClientStoreCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    // used internally to approve records.
    ClientApprovalStoreCommands clientApprovalStoreCommands = null;

    PermissionsStore permissionsStore = null;

    public ClientApprovalStore getClientApprovalStore() {
        return clientApprovalStore;
    }

    public void setClientApprovalStore(ClientApprovalStore clientApprovalStore) {
        this.clientApprovalStore = clientApprovalStore;
    }

    public PermissionsStore getPermissionsStore() {
        return permissionsStore;
    }

    public void setPermissionsStore(PermissionsStore permissionsStore) {
        this.permissionsStore = permissionsStore;
    }

    protected void showCreateHashHelp() {
        say("create_hash string | -file path");
        say("This will create a hash of the given string which is suitable for storing in the database.");
        say("If you specify a file, the entire content will be hashed.");
        say("Note that if there are emebedded blanks, you should enclose the entire argument in double quotes");
        say("E.g. \n\ncreate_hash my pass word");
        say("would just has \"word\", and to get the whole string you should enter" );
        say("create_hash \"my pass word\"");
    }

    public void create_hash(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showCreateHashHelp();
            return;
        }

        String secret = null;
        if (inputLine.hasArg("-file")) {
            try {
                FileReader fis = new FileReader(inputLine.getArg(1 + inputLine.indexOf("-file")));
                StringBuffer sb = new StringBuffer();
                int i;
                while ((i = fis.read()) != -1) {
                    sb.append((char) i);
                }
                fis.close();
                secret = sb.toString();
            } catch (Throwable t) {
                say("Error: could not read file: " + t.getMessage());
                return;
            }
        } else {
            secret = inputLine.getLastArg();
        }
        say("creating hash of " + secret);
        say(DigestUtils.sha1Hex(secret));
    }

    @Override
    protected List<Identifiable> listAll(boolean useLongFormat, String otherFlags) {
        loadAllEntries();

        if (allEntries.isEmpty()) {
            say("(no entries found)");
            return allEntries;
        }
        List<ClientApproval> approvals = getClientApprovalStore().getAll();
        HashMap<Identifier, ClientApproval> approvalMap = new HashMap<>();
        for (ClientApproval a : approvals) {
            approvalMap.put(a.getIdentifier(), a);
        }

        int i = 0;
        getSortable().setState(otherFlags);
        allEntries = getSortable().sort(allEntries);
        for (Identifiable x : allEntries) {
            ClientApproval tempA = approvalMap.get(x.getIdentifier());
            if (tempA == null) {
                tempA = new ClientApproval(x.getIdentifier());
                tempA.setStatus(ClientApproval.Status.NONE);
            }
            if (useLongFormat) {
                longFormat((BaseClient) x, tempA);
            } else {
                say((i++) + ". " + format((BaseClient) x, tempA));
            }
        }
        return allEntries;
    }

    ClientApprovalStore clientApprovalStore;

    protected String format(BaseClient client, ClientApproval ca) {
        String rc = null;
        if (ca == null) {
            rc = "(?) " + client.getIdentifier() + " ";
        } else {
            boolean isApproved = ca != null && ca.isApproved();
            rc = "(" + (isApproved ? "Y" : "N") + ") " + client.getIdentifier() + " ";
        }
        String name = (client.getName() == null ? "no name" : client.getName());
        if (20 < name.length()) {
            name = name.substring(0, 20) + "...";
        }
        rc = rc + "(" + name + ")";
        rc = rc + " created on " + Iso8601.date2String(client.getCreationTS());
        return rc;

    }

    @Override
    protected String format(Identifiable identifiable) {
        BaseClient client = (BaseClient) identifiable;
        ClientApproval ca = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        return format(client, ca);
    }

    protected void longFormat(BaseClient client, ClientApproval clientApproval) {
        say("Client name=" + (client.getName() == null ? "(no name)" : client.getName()));
        sayi("identifier=" + client.getIdentifier());
        sayi("email=" + client.getEmail());
        sayi("creation timestamp=" + client.getCreationTS());
        if (clientApproval == null) {
            sayi("no approval record exists.");
        } else {
            if (clientApproval.isApproved()) {
                String approver = "(unknown)";
                if (clientApproval.getApprover() != null) {
                    approver = clientApproval.getApprover();
                }
                sayi("approved by " + approver);
            } else {
                sayi("not approved");
            }
        }

        if (client.getSecret() == null) {
            sayi("public key: (none)");

        } else {
            sayi("public key:");
            say(client.getSecret());
        }

    }


    @Override
    protected void longFormat(Identifiable identifiable) {
        BaseClient client = (BaseClient) identifiable;
        ClientApproval clientApproval = null;
        if (getClientApprovalStore() != null) {
            clientApproval = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        }
        longFormat(client, clientApproval);

    }


    protected void showApproveHelp() {
        clientApprovalStoreCommands.showApproveHelp();
    }

    public void approve(InputLine inputLine) {
        if (showHelp(inputLine)) {
            showApproveHelp();
            return;
        }

        BaseClient client = (BaseClient) findItem(inputLine);
        ClientApproval ca = null;
        if (getClientApprovalStore().containsKey(client.getIdentifier())) {
            ca = (ClientApproval) getClientApprovalStore().get(client.getIdentifier());
        } else {
            ca = (ClientApproval) getClientApprovalStore().create();
            ca.setIdentifier(client.getIdentifier());
        }
        // now we have the right approval record for this identifier
        clientApprovalStoreCommands.approve(ca);

    }

    @Override
    public boolean update(Identifiable identifiable) {

        BaseClient client = (BaseClient) identifiable;

        String newIdentifier = null;

        info("Starting client update for id = " + client.getIdentifierString());
        say("Update the values. A return accepts the existing or default value in []'s");

        newIdentifier = getInput("enter the identifier", client.getIdentifierString());
        boolean removeCurrentClient = false;
        Identifier oldID = client.getIdentifier();
        BasicIdentifier newID = null;
        if (!newIdentifier.equals(client.getIdentifierString())) {
            sayi2(" replacing client with id=\"" + oldID + "\" with id=\"" + newID + "\" [y/n]? ");
            removeCurrentClient = isOk(readline());
            newID = (BasicIdentifier)BasicIdentifier.newID(newIdentifier);
            client.setIdentifier(newID);
        }

        // no clean way to do this.
        client.setName(getInput("enter the name", client.getName()));
        client.setEmail(getInput("enter email", client.getEmail()));
        // set file not found message.
        extraUpdates(client);
        sayi("here is the complete client:");
        longFormat(client);
        sayi2("save [y/n]?");
        if (isOk(readline())) {
            //getStore().save(client);
            if (removeCurrentClient) {
                // Updating the client_id is non-trivial, as it is the key for
                // not only client records, but also for approval records and
                // is used in the permissions records. updateClient() handles
                // all three. Saving the client record is not done here.
                updateClientID(client,oldID, newID);
            }
            sayi("client updated.");
            info("Client with id " + client.getIdentifierString() + " saving...");

            return true;
        }
        sayi("client not updated, losing changes...");
        info("User terminated updates for client with id " + client.getIdentifierString());
        return false;
    }

    @Override
    public void rm(InputLine inputLine) {

        Identifiable x = findItem(inputLine);
        BaseClient baseClient = (BaseClient)x;
        Identifier baseID = x.getIdentifier();
        String baseIDString = baseClient.getIdentifierString();
        sayi("Removal of client named \"" + baseClient.getName()+"\"");
        sayi("   with id=\"" + baseIDString + "\"");
        String response = getInput("Are you sure you want to remove this client?(y/n)", "n");
        if(!response.equals("y")){
            sayi("aborted...");
            return;
        }
        
        sayi("Removing approval record");
        info("Removing approval record for id=" + baseIDString);
        getClientApprovalStore().remove(baseID);
        sayi("Done. Client approval with id = " + baseIDString + " has been removed from the store");
        info("Client approval record removed for id=" + baseIDString);

        // Also need to remove the permissions (if present)
        PermissionsStore permissionsStore = getPermissionsStore();
        if (permissionsStore!=null) {
            if (baseClient instanceof Client) {
                List<Identifier> admins = permissionsStore.getAdmins(baseID);
                // remove all permissions for this client and these admins
                for (Identifier adminID : admins) {
                    PermissionList permissions = permissionsStore.get(adminID, baseID);
                    for (Permission p : permissions) {
                        sayi("Removing permissions record");
                        info("Removing permissions record for clientID=" + baseIDString);
                        permissionsStore.remove(p.getIdentifier());
                        sayi("Done. permissions for adminID=" + adminID + " / clientID=" + baseIDString + " have been removed from the store");
                        info("Permissions record removed for adminID="  + adminID + " / clientID=" + baseIDString);
                    }
                }
            } else if (baseClient instanceof AdminClient) {
                List<Identifier> clients = permissionsStore.getClients(baseID);
                // remove all permissions for this client and these admins
                for (Identifier clientID : clients) {
                    PermissionList permissions = permissionsStore.get(baseID, clientID);
                    for (Permission p : permissions) {
                        sayi("Removing permissions record");
                        info("Removing permissions record for adminID=" + baseIDString);
                        permissionsStore.remove(p.getIdentifier());
                        sayi("Done. permissions for adminID=" + baseIDString + " / clientID=" + clientID + " have been removed from the store");
                        info("Permissions record removed for adminID=" + baseIDString + " / clientID=" + clientID);
                    }
                }
            } else {
                sayi("Skipping removal of permissions for client " + baseIDString + " of unknown type");
                warn("Skipping removal of permissions for client " + baseIDString + " of unknown type: "+baseClient.getClass().getName());
            }
        }
        super.rm(inputLine);
    }

    /**
     * Updates the client_id in approval and permission records and removes the old
     * client, while saving the new updated client is the responsibility of the caller.
     * @param oldID old client identifier
     * @param newID new client identifier
     */
    protected void updateClientID(BaseClient client, Identifier oldID, Identifier newID){
        info("replacing client with id = " + oldID + " with client with id = " + newID);

        // Update the approval record for the client
        ClientApprovalStore clientApprovalStore = getClientApprovalStore();
        ClientApproval ca = (ClientApproval) clientApprovalStore.get(oldID);
        if (ca != null) {
            ca.setIdentifier(newID);
            clientApprovalStore.remove(oldID);
            clientApprovalStore.save(ca);
        }

        // Update the permission records for the client
        PermissionsStore permissionsStore = getPermissionsStore();
        if (permissionsStore != null) { // not all cli tools have permission stores
            if (client instanceof Client) {
                List<Identifier> admins = permissionsStore.getAdmins(oldID);
                // update all permissions for this client and these admins
                for (Identifier adminID : admins) {
                    PermissionList permissions = permissionsStore.get(adminID, oldID);
                    for (Permission p : permissions) {
                        // Update the clientID for the given permission
                        p.setClientID(newID);
                        // Store the update entry
                        permissionsStore.save(p);
                    }
                }
            } else if (client instanceof AdminClient) {
                List<Identifier> clients = permissionsStore.getClients(oldID);
                // remove all permissions for this admin and these clients
                for (Identifier clientID : clients) {
                    PermissionList permissions = permissionsStore.get(oldID, clientID);
                    for (Permission p : permissions) {
                        // Update the clientID for the given permission
                        p.setAdminID(newID);
                        // Store the update entry
                        permissionsStore.save(p);
                    }
                }
            } else {
                sayi("Skipping updating of permissions for client " + newID + " of unknown type");
                warn("Skipping updating of permissions for client " + newID + " of unknown type: "+client.getClass().getName());
            }

        }

        // NOTE: we remove the old entry here from the store, but the
        // client object (our argument) is now changed and will be
        // re-stored in edu.uiuc.ncsa.security.util.cli.StoreCommands.update()
        getStore().remove(oldID);

        sayi("client with id " + oldID + " replaced with id " + newID + ". Be sure to adapt clients.");
        info("client with id " + oldID + " is now client with id " + newID);
    }
}
