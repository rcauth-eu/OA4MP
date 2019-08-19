package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.permissions;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.cm.util.AbstractDDServer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.Permission;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionList;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

import java.util.LinkedList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/1/16 at  10:54 AM
 */
public class PermissionServer extends AbstractDDServer {
    public PermissionServer(OA2SE cose) {
        super(cose);
    }

    /**
     * Returns a list of admins for a given client. This will check that the permissions exist for this operation.
     *
     * @param request
     * @return
     */
    public PermissionResponse listAdmins(ListAdminsRequest request) {
        // request needs an client id
        // canRead(request);
        Identifier clientID = request.getClient().getIdentifier();
        List<Identifier> adminIDs = getPermissionStore().getAdmins(clientID);
        List<AdminClient> admins = new LinkedList<>();
        for (Identifier id : adminIDs) {
            try {
                // NOTE: since we use the permission store to get the list of adminIDs for given clientID,
                // there is no point in checking whether for given combination indeed a permission exists.
//              getPermissionStore().get(id, clientID);
                AdminClient adminClient = getAdminClientStore().get(id);
                if (adminClient==null)
                    // NOTE: this situation means an inconsistency between the DB tables.
                    cose.getMyLogger().error("non-existent adminClient in permissions table: adminID="+id+" (clientID="+clientID+")");
                else
                    admins.add(adminClient);
            } catch (Throwable t) {
                // rock on
            }
        }
        return new ListAdminsResponse(admins);
    }


    public PermissionResponse listClients(ListClientsRequest request) {
        // request needs an admin client only
//        canRead(request);
        Identifier adminID = request.getAdminClient().getIdentifier();
        List<Identifier> clientIDs = getPermissionStore().getClients(adminID);
        List<OA2Client> clients = new LinkedList<>();
        for (Identifier id : clientIDs) {
            try {
                // NOTE: since we use the permission store to get the list of clientIDs for given adminID,
                // there is no point in checking whether for given combination indeed a permission exists.
//              getPermissionStore().get(adminID, id);
                OA2Client client = (OA2Client) getClientStore().get(id);
                if (client==null)
                    // NOTE: this situation means an inconsistency between the DB tables.
                    cose.getMyLogger().error("non-existent client in permissions table: clientID="+id+" (adminID="+adminID+")");
                else
                    clients.add(client);
            } catch (Throwable throwable) {
                // rock on if not allowed
            }
        }
        return new ListClientResponse(clients);
    }

    /**
     * removes a client from management by an admin. This does NOT remove the client!!
     *
     * @param request
     * @return
     */
    public PermissionResponse removeClient(RemoveClientRequest request) {
        // request needs admin as src, client as target
        canWrite(request);
        PermissionList permissionList = getPermissionStore().get(request.getAdminClient().getIdentifier(), request.getClient().getIdentifier());
        // remove all of these permissions
        for (Permission p : permissionList) {
            getPermissionStore().remove(p.getIdentifier());
        }
        return new PermissionResponse();
    }

    /**
     * Adds a given client to the list of clients managed by this admin
     *
     * @param request
     * @return
     */
    public PermissionResponse addClient(AddClientRequest request) {
        //request needs admin and client.
        // Check if there is one already -- don't fill up table with redundant permissions.
        Permission p = null;
        PermissionList pList = getPermissionStore().get(request.getAdminClient().getIdentifier(), request.getClient().getIdentifier());
        switch (pList.size()) {
            case 0:
                p = getPermissionStore().create();
                break;
            case 1:
                p = pList.get(0);
                break;
            default:
                throw new GeneralException("Internal error. Multiple permissiions entries found");

        }
        p.setAdminID(request.getAdminClient().getIdentifier());
        p.setClientID(request.getClient().getIdentifier());
        p.setApprove(true);
        p.setCreate(true);
        p.setDelete(true);
        p.setRead(true);
        p.setWrite(true);
        getPermissionStore().save(p);
        return new AddClientResponse();
    }

}
