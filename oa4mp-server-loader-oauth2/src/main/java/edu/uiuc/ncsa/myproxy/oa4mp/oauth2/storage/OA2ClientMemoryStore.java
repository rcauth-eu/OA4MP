package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.security.core.IdentifiableProvider;
import edu.uiuc.ncsa.security.delegation.server.storage.impl.ClientMemoryStore;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/2/16 at  2:09 PM
 */
public class OA2ClientMemoryStore<V extends OA2Client> extends ClientMemoryStore<V> {

    public OA2ClientMemoryStore(IdentifiableProvider<V> vIdentifiableProvider) {
        super(vIdentifiableProvider);
    }

    @Override
    public MapConverter getMapConverter() {
        return new OA2ClientConverter(this.identifiableProvider);
    }
}
