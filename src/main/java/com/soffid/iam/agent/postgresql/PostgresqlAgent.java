package com.soffid.iam.agent.postgresql;

import java.math.BigDecimal;
import java.rmi.RemoteException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import org.postgresql.Driver;

import com.soffid.iam.api.Account;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.ObjectMappingTrigger;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.SoffidObjectType;
import com.soffid.iam.api.User;
import com.soffid.iam.sync.agent.Agent;
import com.soffid.iam.sync.engine.extobj.AccountExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ExtensibleObjectFinder;
import com.soffid.iam.sync.engine.extobj.GrantExtensibleObject;
import com.soffid.iam.sync.engine.extobj.ObjectTranslator;
import com.soffid.iam.sync.engine.extobj.RoleExtensibleObject;
import com.soffid.iam.sync.engine.extobj.UserExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObject;
import com.soffid.iam.sync.intf.ExtensibleObjectMapping;
import com.soffid.iam.sync.intf.ExtensibleObjectMgr;
import com.soffid.iam.sync.intf.ReconcileMgr2;
import com.soffid.iam.sync.intf.RoleMgr;
import com.soffid.iam.sync.intf.UserMgr;

import es.caib.seycon.ng.comu.SoffidObjectTrigger;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.bootstrap.NullSqlObjet;
import es.caib.seycon.ng.sync.bootstrap.QueryHelper;

/**
 * Agente SEYCON para gestionar bases de datos Oracle
 * <P>
 */

public class PostgresqlAgent extends Agent implements UserMgr, RoleMgr,
		ReconcileMgr2, ExtensibleObjectMgr {
	private static final String PASSWORD_QUOTE_REPLACEMENT = "'";
	/** Usuario Oracle */
	transient String user;
	/** Contraseña oracle */
	transient Password password;
	/** Cadena de conexión a la base de datos */
	transient String db;
	/** Valor que activa o desactiva el debug */
	transient boolean debug;
	/**
	 * Hash de conexiones ya establecidas. De esta forma se evita que el agente
	 * seycon abra conexiones sin control debido a problemas de comunicaciones
	 * con el servidor
	 */
	static Hashtable hash = new Hashtable();

	/* versió dels triggers del control d'accés */
	private final static String VERSIO = "2.0"; //$NON-NLS-1$

	/**
	 * Constructor
	 * 
	 * @param params
	 *            vector con parámetros de configuración: <LI>0 = usuario</LI>
	 *            <LI>1 = contraseña oracle</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
	 */
	public PostgresqlAgent() throws java.rmi.RemoteException {
		super();
	}

	private String sentence(String cmd) {
		return sentence(cmd, null);
	}

	protected String sentence(String cmd, Password pass) {
		if (debug)
			if (pass == null)
				log.info(cmd);
			else
				log.info(cmd.replace(quotePassword(pass), "******"));
		return cmd;
	}

	/**
	 * Inicializar el agente.
	 */
	public void init() throws InternalErrorException {
		log.info("Starting Postgresql agent {}", getSystem().getName(), null); //$NON-NLS-1$
		user = getSystem().getParam0();
		if (getSystem().getParam1() != null) {
			try {
				password = Password.decode(getSystem().getParam1());
			} catch (Exception e) {
				password = null;
			}
		}
		db = getSystem().getParam2();
		debug = "true".equals(getSystem().getParam4());
		if (debug) {
			log.info("user: "+user);
			log.info("password: ********");
			log.info("db: "+db);
			log.info("rolePassword: ********");
			log.info("debug: "+debug);
		}
		getConnection();
		releaseConnection();
	}

	/**
	 * Liberar conexión a la base de datos. Busca en el hash de conexiones
	 * activas alguna con el mismo nombre que el agente y la libera. A
	 * continuación la elimina del hash. Se invoca desde el método de gestión de
	 * errores SQL.
	 */
	public void releaseConnection() {
		Connection conn = (Connection) hash.get(this.getSystem().getName());
		if (conn != null) {
			hash.remove(this.getSystem().getName());
			try {
				conn.close();
			} catch (SQLException e) {
			}
		}
	}

	/**
	 * Obtener una conexión a la base de datos. Si la conexión ya se encuentra
	 * establecida (se halla en el hash de conexiones activas), simplemente se
	 * retorna al método invocante. Si no, registra el driver oracle, efectúa la
	 * conexión con la base de datos y la registra en el hash de conexiones
	 * activas
	 * 
	 * @return conexión SQL asociada.
	 * @throws InternalErrorException
	 *             algún error en el proceso de conexión
	 */
	boolean disableSysdba = false;
	private Collection<ExtensibleObjectMapping> objectMappings;
	private ObjectTranslator objectTranslator;
	public Connection getConnection() throws InternalErrorException {
		Connection conn = (Connection) hash.get(this.getSystem().getName());
		if (conn == null) {
			try {
				DriverManager
						.registerDriver(new Driver());
				// Connect to the database
				conn = DriverManager.getConnection(db, user, password.getPassword());
				hash.put(this.getSystem().getName(), conn);
			} catch (SQLException e) {
				log.info("Error connecting to the database",e);
				throw new InternalErrorException(
						Messages.getString("PostgresqlAgent.ConnectionError"), e); //$NON-NLS-1$
			}
		}
		return conn;
	}

	/**
	 * Gestionar errores SQL. Debe incovarse cuando se produce un error SQL. Si
	 * el sistema lo considera oportuno cerrará la conexión SQL.
	 * 
	 * @param e
	 *            Excepción oralce producida
	 * @throws InternalErrorExcepción
	 *             error que se debe propagar al servidor (si es neceasario)
	 */
	public void handleSQLException(SQLException e)
			throws InternalErrorException {
		if (debug) 
			log.warn(this.getSystem().getName() + " SQL Exception: ", e); //$NON-NLS-1$
		releaseConnection();
		throw new InternalErrorException("Error ejecutando sentencia SQL", e);
	}

	/**
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y
	 * le asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user
	 *            código de usuario
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUser(Account account, User usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		String user = account.getName();
		// boolean active;
		PreparedStatement stmt = null;
		Statement stmt2 = null;
		ResultSet rset = null;
		// String groupsConcat = "";
		Collection<RoleGrant> roles;
		Collection<Group> groups;

		String groupsAndRoles[];
		int i;

		// Control de acceso (tabla de roles)
		boolean cacActivo = false; // indica si está activo el control de acceso
		PreparedStatement stmtCAC = null;
		ResultSet rsetCAC = null;

		try {
			// Obtener los datos del usuario
			roles = getServer().getAccountRoles(user,
					this.getSystem().getName());

			groups = null;
			groupsAndRoles = concatUserGroupsAndRoles(groups, roles);

			Connection sqlConnection = getConnection();
			stmt2 = sqlConnection.createStatement();
			// Comprobar si el usuario existe
			stmt = sqlConnection
					.prepareStatement(sentence("SELECT 1 FROM pg_role WHERE rolname=?")); //$NON-NLS-1$
			stmt.setString(1, user);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			final boolean newObject = !rset.next();
			if (newObject) {
				stmt.close();

				Password pass = getServer().getOrGenerateUserPassword(user,
						getSystem().getName());

				String cmd = "CREATE USER \"" + user + "\" PASSWORD '"+quotePassword(pass);
				cmd += "' NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION ";
				
				if (! runTriggers(SoffidObjectType.OBJECT_USER, SoffidObjectTrigger.PRE_INSERT, new UserExtensibleObject(account, usu, getServer()))) {
					if (debug)
						log.info("Ignoring creation of user "+account.getName()+" due to pre-insert trigger failure");
					return;
				}
				stmt = sqlConnection.prepareStatement(sentence(cmd, pass));
				stmt.execute();
			} else {
				if (! runTriggers(SoffidObjectType.OBJECT_USER, SoffidObjectTrigger.PRE_UPDATE, new UserExtensibleObject(account, usu, getServer()))) {
					if (debug)
						log.info("Ignoring creation of user "+account.getName()+" due to pre-insert trigger failure");
					return;
				}
				
			}
			// System.out.println ("Usuario "+user+" ya existe");
			rset.close();
			stmt.close();

			stmt = sqlConnection
					.prepareStatement(sentence("ALTER USER \"" + user + "\" LOGIN")); //$NON-NLS-1$ //$NON-NLS-2$
			stmt.execute();
			stmt.close();

			// Eliminar los roles que sobran
			stmt = sqlConnection
					.prepareStatement(sentence("select rolname from pg_auth_members, pg_user, pg_roles where member=usesysid and roleid=oid and usename=?")); //$NON-NLS-1$
			stmt.setString(1, user);
			rset = stmt.executeQuery();
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);
				for (i = 0; groupsAndRoles != null && !found
						&& i < groupsAndRoles.length; i++) {
					if (groupsAndRoles[i] != null
							&& groupsAndRoles[i].equalsIgnoreCase(role)) {
						found = true;
						groupsAndRoles[i] = null;
					}
				}
				if (!found) {
					RoleGrant r = new RoleGrant();
					r.setRoleName(role);
					r.setSystem(getAgentName());
					r.setOwnerAccountName(account.getName());
					r.setOwnerSystem(account.getSystem());
					if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer()))) 
					{
						stmt2.execute(sentence("REVOKE \"" + role + "\" FROM \"" + user + "\"")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())); 
					} else {
						if (debug)
							log.info("Grant not revoked due to pre-delete trigger failure");
					}

				}
			}
			rset.close();
			stmt.close();

			String rolesPorDefecto = null;

			// Crear los roles si son necesarios
			for (RoleGrant r : roles) {
				if (r != null) {
					// if(r.){
					if (rolesPorDefecto == null)
						rolesPorDefecto = "\"" + r.getRoleName() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					else
						rolesPorDefecto = rolesPorDefecto + ",\"" + //$NON-NLS-1$
								r.getRoleName() + "\""; //$NON-NLS-1$
					// }
					stmt = sqlConnection
							.prepareStatement(sentence("SELECT 1 FROM pg_roles where rolname=?")); //$NON-NLS-1$
					stmt.setString(1, r.getRoleName());
					rset = stmt.executeQuery();
					if (!rset.next()) {
						Role role = getServer().getRoleInfo(r.getRoleName(), getAgentName());
						if ( runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.PRE_INSERT, new com.soffid.iam.sync.engine.extobj.RoleExtensibleObject(role, getServer())) ) 
						{
							// Password protected or not
							String command = "CREATE ROLE \"" + r.getRoleName() + "\" NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION"; //$NON-NLS-1$ //$NON-NLS-2$
							stmt2.execute(sentence(command));
							runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.POST_INSERT, new com.soffid.iam.sync.engine.extobj.RoleExtensibleObject(role, getServer()));
						} else {
							if (debug)
								log.info("Grant not executed due to pre-insert trigger failure");
						}
					}
					rset.close();
					stmt.close();
				}
			}

			// Añadir los roles que no tiene
			for (i = 0; /* active && */groupsAndRoles != null
					&& i < groupsAndRoles.length; i++) {
				if (groupsAndRoles[i] != null) {
					RoleGrant r = new RoleGrant();
					r.setRoleName(groupsAndRoles[i]);
					r.setSystem(getAgentName());
					r.setOwnerAccountName(account.getName());
					r.setOwnerSystem(account.getSystem());
					if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer()))) 
					{
						sqlConnection.createStatement().execute("GRANT \"" + groupsAndRoles[i] + "\" TO  \"" + user + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())); 
					} else {
						if (debug)
							log.info("Grant not executed due to pre-insert trigger failure");
					}
				}
			}

			runTriggers(SoffidObjectType.OBJECT_USER, newObject ? SoffidObjectTrigger.POST_INSERT : SoffidObjectTrigger.POST_UPDATE, new UserExtensibleObject(account, usu, getServer()));

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.ProcessingTaskError"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
	}

	protected String quotePassword(Password pass) {
		return pass.getPassword().replaceAll("\'", "''");
	}

	/**
	 * Actualizar la contraseña del usuario. Asigna la contraseña si el usuario
	 * está activo y la contraseña no es temporal. En caso de contraseñas
	 * temporales, asigna un contraseña aleatoria.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @param mustchange
	 *            es una contraseña temporal?
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUserPassword(String user, User arg1, Password password,
			boolean mustchange)
			throws es.caib.seycon.ng.exception.InternalErrorException {
		if (debug) log.info("updateUserPassword");
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			Account acc = getServer().getAccountInfo(user, getAgentName());
			// Comprobar si el usuario existe
			Connection sqlConnection = getConnection();
			stmt = sqlConnection
					.prepareStatement(sentence("SELECT rolname from pg_roles " + //$NON-NLS-1$
							"WHERE rolname=?")); //$NON-NLS-1$ //$NON-NLS-2$
			stmt.setString(1, user);
			ResultSet rset = stmt.executeQuery();
			if (rset.next() && password.getPassword().length() > 0) {
				stmt.close();
				if (arg1 == null) {
					if (! runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_UPDATE, new AccountExtensibleObject(acc, getServer()))) 
						return;
				}
				else {
					if (! runTriggers(SoffidObjectType.OBJECT_USER, SoffidObjectTrigger.PRE_UPDATE, new UserExtensibleObject(acc, arg1, getServer()))) 
						return;
				}
					
				cmd = "ALTER USER \"" + user + "\" PASSWORD '"+quotePassword(password)+"' LOGIN"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd, password));
				stmt.execute();
				if (arg1 == null) {
					if (! runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.POST_UPDATE, new AccountExtensibleObject(acc, getServer()))) 
						return;
				}
				else {
					if (! runTriggers(SoffidObjectType.OBJECT_USER, SoffidObjectTrigger.POST_UPDATE, new UserExtensibleObject(acc, arg1, getServer()))) 
						return;
				}
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e2) {
				}
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.UpdatingPasswordError"), e); //$NON-NLS-1$
		} finally {
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
	}

	/**
	 * Validar contraseña.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @return false
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public boolean validateUserPassword(String user, Password password)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			Connection conn = DriverManager.getConnection(db, user, password.getPassword());
			conn.close();
			return true;
		} catch (SQLException e) {
			log.info("Error validating password for "+user+": "+e.getMessage());
		}
		return false;
	}

	/**
	 * Concatenar los vectores de grupos y roles en uno solo. Si el agente está
	 * basado en roles y no tiene ninguno, retorna el valor null
	 * 
	 * @param groups
	 *            vector de grupos
	 * @param roles
	 *            vector de roles
	 * @return vector con nombres de grupo y role
	 */
	public String[] concatUserGroupsAndRoles(Collection<Group> groups,
			Collection<RoleGrant> roles) {
		int i;
		int j;

		if (roles.isEmpty() && getSystem().getRolebased()) // roles.length == 0
															// && getRoleBased
															// ()
			return null;
		LinkedList<String> concat = new LinkedList<String>();
		if (groups != null) {
			for (Group g : groups)
				concat.add(g.getName());
		}
		for (RoleGrant rg : roles) {
			concat.add(rg.getRoleName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	public String[] concatRoleNames(Collection<RoleGrant> roles) {
		if (roles.isEmpty() && getSystem().getRolebased())
			return null;

		LinkedList<String> concat = new LinkedList<String>();
		for (RoleGrant rg : roles) {
			concat.add(rg.getRoleName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String,
	 * java.lang.String)
	 */
	public void updateRole(Role ri) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		String bd = ri.getSystem();
		String role = ri.getName();
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			if (this.getSystem().getName().equals(bd)) {
				// Comprobar si el rol existe en la bd
				Connection sqlConnection = getConnection();
				stmt = sqlConnection
						.prepareStatement(sentence("SELECT rolname from pg_roles " + //$NON-NLS-1$
								"WHERE rolname=?")); //$NON-NLS-1$ //$NON-NLS-2$
				stmt.setString(1, role);
				ResultSet rset = stmt.executeQuery();
				if (!rset.next()) // aquest rol NO existeix com a rol de la BBDD
				{
					if (ri != null) {// si el rol encara existeix al seycon (no
										// s'ha esborrat)
						if ( runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.PRE_INSERT, new RoleExtensibleObject(ri, getServer())) )  {
							stmt.close();
							cmd = "CREATE ROLE \"" + role + "\" NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION"; //$NON-NLS-1$ //$NON-NLS-2$
							stmt = sqlConnection.prepareStatement(sentence(cmd));
							stmt.execute();
							// Fem un revoke per a l'User SYSTEM (CAI-579530:
							// u88683)
							stmt.close();
							stmt = sqlConnection
									.prepareStatement(sentence("REVOKE \"" + role + "\" FROM \"" + user + "\"")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
							stmt.execute();
	
							runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.POST_INSERT, new RoleExtensibleObject(ri, getServer())) ;
						} else {
							if (debug)
								log.info("Creation of role "+ri.getName()+" ignored due to pre-insert trigger failure");
						}
					}
				}
				stmt.close();
				rset.close();
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e2) {
				}
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.ErrorUpdatingRole"), e); //$NON-NLS-1$
		}
	}


	public void removeRole(String nom, String bbdd) {
		try {
			Connection sqlConnection = getConnection();
			if (this.getSystem().getName().equals(bbdd)) {
				Role ri = new Role();
				ri.setName(nom);
				ri.setSystem(bbdd);
				PreparedStatement stmtCAC = null;
				if ( runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.PRE_DELETE, new RoleExtensibleObject(ri, getServer())) )  {
					stmtCAC = sqlConnection
							.prepareStatement(sentence("DROP ROLE \"" + nom + "\"")); //$NON-NLS-1$ //$NON-NLS-2$
					stmtCAC.execute();
					stmtCAC.close();
					runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.POST_DELETE, new RoleExtensibleObject(ri, getServer()));
				} else {
					if (debug)
						log.info("Removal of role "+nom+" has been ignored due to pre-delete trigger failure");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public void removeUser(String arg0) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		if (debug) log.info("removeUser");
		try {
			Account account = getServer().getAccountInfo(arg0, getAgentName());
			if (account == null || account.getStatus() == AccountStatus.REMOVED)
			{
				// Comprobar si el usuario existe
				Connection sqlConnection = getConnection();
				PreparedStatement stmt = null;
				stmt = sqlConnection
						.prepareStatement(sentence("SELECT 1 FROM pg_roles WHERE rolname=?")); //$NON-NLS-1$
				stmt.setString(1, arg0);
				ResultSet rset = stmt.executeQuery();
				// Determinar si el usuario está o no activo
				// Si no existe darlo de alta
				if (rset.next()) {
					if (account == null) {
						account = new Account();
						account.setName(arg0);
						account.setSystem(getAgentName());
					}
					if ( runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_DELETE, new AccountExtensibleObject(account, getServer())) )  {
						rset.close();
						stmt.close();
						if (debug) log.info("Dropping user "+arg0);
						stmt = sqlConnection
								.prepareStatement(sentence("DROP USER \"" + arg0 + "\"")); //$NON-NLS-1$ //$NON-NLS-2$
						try {
							stmt.execute();
						} catch (SQLException e) {
							handleSQLException(e);
						} finally {
							stmt.close();
						}
						runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.POST_DELETE, new AccountExtensibleObject(account, getServer()));
					} else {
						if (debug)
							log.info("Removal of account "+arg0+" has been ignored due to pre-delete trigger failure");
					}
				}
				else
					stmt.close();
			}
			else
			{
				if ( runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_UPDATE, new AccountExtensibleObject(account, getServer())) )  {
					Connection sqlConnection = getConnection();
					PreparedStatement stmt = null;
					stmt = sqlConnection
							.prepareStatement(sentence("ALTER USER \"" + arg0 + "\" nologin")); //$NON-NLS-1$ //$NON-NLS-2$
					stmt.execute();
					stmt.close();
	
					runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.POST_UPDATE, new AccountExtensibleObject(account, getServer()));
					removeRoles (sqlConnection, arg0);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.318"), e); //$NON-NLS-1$
		}
	}

	private void removeRoles(Connection sqlConnection, String accountName) throws SQLException, InternalErrorException {
		PreparedStatement stmt = sqlConnection
				.prepareStatement(sentence("select rolname from pg_auth_members, pg_user, pg_roles where member=usesysid and roleid=oid AND usename=?")); //$NON-NLS-1$
		stmt.setString(1, accountName);
		ResultSet rset = stmt.executeQuery();
		Statement stmt2 = sqlConnection.createStatement();
		while (rset.next()) {
			String role = rset.getString(1);

			RoleGrant r = new RoleGrant();
			r.setRoleName(role);
			r.setSystem(getAgentName());
			r.setOwnerAccountName(accountName);
			r.setOwnerSystem(getSystem().getName());

			if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
					runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
					runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
					runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
					runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer()))) 
			{
				stmt2.execute("REVOKE \"" + role + "\" FROM \"" + accountName + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
						runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
						runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
						runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
						runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())); 
			} else {
				if (debug)
					log.info("Grant not revoked due to pre-delete trigger failure");
			}
		}
		rset.close();
		stmt.close();
	}

	public void updateUser(Account acc)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		if (debug) log.info("updateUser(String nom, String descripcio)");
		PreparedStatement stmt = null;
		Statement stmt2 = null;
		ResultSet rset = null;

		
		String accountName = acc.getName();
		Collection<RoleGrant> roles;

		int i;

		// Control de acceso (tabla de roles)
		boolean cacActivo = false; // indica si está activo el control de acceso
		PreparedStatement stmtCAC = null;
		ResultSet rsetCAC = null;

		try {
			// Obtener los datos del usuario
			roles = getServer().getAccountRoles(accountName,
					this.getSystem().getName());

			Connection sqlConnection = getConnection();

			// Comprobar si el usuario existe
			stmt = sqlConnection
					.prepareStatement(sentence("SELECT 1 FROM pg_roles WHERE rolname=?")); //$NON-NLS-1$
			stmt.setString(1, accountName);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			final boolean newUser = !rset.next();
			if (newUser) {
				stmt.close();

				Password pass = getServer().getOrGenerateUserPassword(accountName,
						getSystem().getName());

				if (! runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_INSERT, new AccountExtensibleObject(acc, getServer()))) {
					if (debug)
						log.info("Ignoring creation of user "+acc.getName()+" due to pre-insert trigger failure");
					return ;
				}

				String cmd = "CREATE USER \"" + accountName + "\" PASSWORD '"+quotePassword(pass);
				cmd += "' NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION";

				stmt = sqlConnection.prepareStatement(sentence(cmd));
				stmt.execute();
			} else {
				if (! runTriggers(SoffidObjectType.OBJECT_ACCOUNT, SoffidObjectTrigger.PRE_UPDATE, new AccountExtensibleObject(acc, getServer()))) {
					if (debug)
						log.info("Ignoring update of user "+acc.getName()+" due to pre-update trigger failure");
					return;
				}
				

			}

			rset.close();
			stmt.close();

			// Eliminar los roles que sobran
			stmt = sqlConnection
					.prepareStatement(sentence("select rolname from pg_auth_members, pg_user, pg_roles where member=usesysid and roleid=oid AND usename=?")); //$NON-NLS-1$
			stmt.setString(1, accountName);
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.createStatement();
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);

				for (RoleGrant ro : roles) {
					if (ro != null && ro.getRoleName().equalsIgnoreCase(role)) {
						found = true;
						ro = null;
					}
				}
				if (!found) {
					RoleGrant r = new RoleGrant();
					r.setRoleName(role);
					r.setSystem(getAgentName());
					r.setOwnerAccountName(acc.getName());
					r.setOwnerSystem(acc.getSystem());

					if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_DELETE, new GrantExtensibleObject(r, getServer()))) 
					{
						stmt2.execute("REVOKE \"" + role + "\" FROM \"" + accountName + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_DELETE, new GrantExtensibleObject(r, getServer())); 
					} else {
						if (debug)
							log.info("Grant not revoked due to pre-delete trigger failure");
					}
				}
			}
			rset.close();
			stmt.close();

			String rolesPorDefecto = null;

			// Crear los roles si son necesarios
			for (RoleGrant r : roles) {
				if (r != null) {
					if (rolesPorDefecto == null)
						rolesPorDefecto = "\"" + r.getRoleName() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					else
						rolesPorDefecto = rolesPorDefecto
								+ ",\"" + r.getRoleName() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					stmt = sqlConnection
							.prepareStatement(sentence("SELECT 1 FROM pg_roles WHERE rolname=?")); //$NON-NLS-1$
					stmt.setString(1, r.getRoleName());
					rset = stmt.executeQuery();
					if (!rset.next()) {
						Role role = getServer().getRoleInfo(r.getRoleName(), getAgentName());
						if ( runTriggers(SoffidObjectType.OBJECT_ROLE, SoffidObjectTrigger.PRE_INSERT, new com.soffid.iam.sync.engine.extobj.RoleExtensibleObject(role, getServer())) ) 
						{
							// Password protected or not
							String command = "CREATE ROLE \"" + r.getRoleName() + "\" NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION"; //$NON-NLS-1$ //$NON-NLS-2$
							stmt2.execute(command);
						} else {
							if (debug)
								log.info("Grant not executed due to pre-insert trigger failure");
						}
					}
					rset.close();
					stmt.close();
				}
			}

			// Añadir los roles que no tiene
			for (RoleGrant r : roles) {
				if (r != null) {
					if ( runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer())) &&
							runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.PRE_INSERT, new GrantExtensibleObject(r, getServer()))) 
					{
						stmt2.execute("GRANT \"" + r.getRoleName() + "\" TO  \"" + accountName + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						boolean ok = runTriggers(SoffidObjectType.OBJECT_GRANT, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_GROUP, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_ALL_GRANTED_ROLES, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_GROUP, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())) &&
								runTriggers(SoffidObjectType.OBJECT_GRANTED_ROLE, SoffidObjectTrigger.POST_INSERT, new GrantExtensibleObject(r, getServer())); 
					} else {
						if (debug)
							log.info("Grant not executed due to pre-insert trigger failure");
					}
				}
			}

			runTriggers(SoffidObjectType.OBJECT_ACCOUNT, newUser ? SoffidObjectTrigger.POST_INSERT : SoffidObjectTrigger.POST_UPDATE, new AccountExtensibleObject(acc, getServer()));

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> accounts = new LinkedList<String>();
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		Collection<RoleGrant> roles;

		int i;

		// Control de acceso (tabla de roles)
		boolean cacActivo = false; // indica si está activo el control de acceso
		PreparedStatement stmtCAC = null;
		ResultSet rsetCAC = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("SELECT usename from pg_user")); //$NON-NLS-1$
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				accounts.add(rset.getString(1));
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return accounts;
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		// Control de acceso (tabla de roles)
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("SELECT rolname, rolcanlogin from pg_roles where rolname=?")); //$NON-NLS-1$
			stmt.setString(1, userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				Account account = new Account ();
				account.setName(userAccount);
				account.setDescription(userAccount);
				account.setSystem(getAgentName());
				account.setDisabled(! rset.getBoolean(2));
				return account;
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> roles = new LinkedList<String>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("select rolname from pg_roles")); //$NON-NLS-1$
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				roles.add(rset.getString(1));
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
		return roles;
	}

	public Role getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		// Control de acceso (tabla de roles)
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("SELECT rolname from pg_roles where rolname=?")); //$NON-NLS-1$
			stmt.setString(1, roleName);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				Role r = new Role();
				r.setSystem(getAgentName());
				r.setName(rset.getString(1));
				r.setDescription(rset.getString(1));
				return r;
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return null;
	}

	public List<RoleGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		LinkedList<RoleGrant> roles = new LinkedList<RoleGrant>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement(sentence("select rolname from pg_auth_members, pg_user, pg_roles where meber=usesysid and roleid=oid AND usename=?")); //$NON-NLS-1$
			stmt.setString(1,  userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				RoleGrant rg = new RoleGrant();
				rg.setSystem(getAgentName());
				rg.setRoleName(rset.getString(1));
				rg.setOwnerAccountName(userAccount);
				rg.setOwnerSystem(getAgentName());
				roles.add(rg);
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("PostgresqlAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
		return roles;
	}
	
	private boolean runTriggers(SoffidObjectType objectType, SoffidObjectTrigger triggerType, 
			ExtensibleObject src) throws InternalErrorException {
		List<ObjectMappingTrigger> triggers = getTriggers (objectType, triggerType);
		for (ObjectMappingTrigger trigger: triggers)
		{
	
			ExtensibleObject eo = new ExtensibleObject();
			eo.setAttribute("source", src);
			eo.setAttribute("newObject", new HashMap());
			eo.setAttribute("oldObject", new HashMap());
			if ( ! objectTranslator.evalExpression(eo, trigger.getScript()) )
			{
				log.info("Trigger "+trigger.getTrigger().toString()+" returned false");
				return false;
			}
		}
		return true;
	}

	private List<ObjectMappingTrigger> getTriggers(SoffidObjectType objectType, SoffidObjectTrigger type) {
		List<ObjectMappingTrigger> triggers = new LinkedList<ObjectMappingTrigger>();
		if (objectMappings != null) {
			for ( ExtensibleObjectMapping objectMapping: objectMappings)
			{
				if (objectMapping.getSoffidObject().toString().equals(objectType.toString()))
				{
					for ( ObjectMappingTrigger trigger: objectMapping.getTriggers())
					{
						if (trigger.getTrigger() == type)
							triggers.add(trigger);
					}
				}
			}
		}
		return triggers;
	}

	public Collection<Map<String, Object>> invoke(String verb, String command,
			Map<String, Object> params) throws RemoteException, InternalErrorException 
	{
		ExtensibleObject o = new ExtensibleObject();
		if (params != null)
		o.putAll(params);
		if (command == null)
			command = "";
		if (verb != null && !verb.trim().isEmpty())
			command = verb.trim() + " " +command;
		List<Map<String, Object>> result = new LinkedList<Map<String,Object>>();
		executeSentence(command, o, null, result );
		return result;
	}

	public void configureMappings(Collection<ExtensibleObjectMapping> objects)
			throws RemoteException, InternalErrorException {
		this.objectMappings = objects;
		objectTranslator = new ObjectTranslator(getSystem(), getServer(), objectMappings);
		objectTranslator.setObjectFinder(finder);
	}

	public ExtensibleObject getNativeObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	public ExtensibleObject getSoffidObject(SoffidObjectType type, String object1, String object2)
			throws RemoteException, InternalErrorException {
		return null;
	}

	ExtensibleObjectFinder finder = new ExtensibleObjectFinder() {
		
		public Collection<Map<String, Object>> invoke(String verb, String command, Map<String, Object> params)
				throws InternalErrorException {
			try {
				return PostgresqlAgent.this.invoke(verb, command, params);
			} catch (RemoteException e) {
				throw new InternalErrorException("Error executing command "+verb+" "+command, e);
			}
		}
		
		public ExtensibleObject find(ExtensibleObject pattern) throws Exception {
			return null;
		}
	};
	
	private int executeSentence(String sentence, ExtensibleObject obj, String filter, List<Map<String, Object>> result) throws InternalErrorException {
		StringBuffer b = new StringBuffer ();
		List<Object> parameters = new LinkedList<Object>();
		if (result != null)
			result.clear();
		
		Object cursor = new Object();
		parseSentence(sentence, obj, b, parameters, cursor);
		
		String parsedSentence = b.toString().trim();
		
		if (debug)
		{
			log.info("Executing "+parsedSentence);
			for (Object param: parameters)
			{
				log.info("   Param: "+(param == null ? "null": param.toString()+" ["
						+param.getClass().toString()+"]"));
			}
		}
		
		Connection conn;
		try {
			conn = getConnection();
			conn.setAutoCommit(true);
		} catch (Exception e1) {
			throw new InternalErrorException("Error connecting to database ", e1);
		}
		if (parsedSentence.toLowerCase().startsWith("select"))
		{
			if (debug)
				log.info("Getting rows");
			QueryHelper qh = new QueryHelper(conn);
			qh.setEnableNullSqlObject(true);
			try {
				List<Object[]> rows = qh.select(parsedSentence, parameters.toArray());
				log.info("Got rows size = "+rows.size());
				int rowsNumber = 0;
				for (Object[] row: rows)
				{
					if (debug)
						log.info("Got row ");
					ExtensibleObject eo = new ExtensibleObject();
					eo.setObjectType(obj.getObjectType());
					for (int i = 0; i < row.length; i ++)
					{
						String param = qh.getColumnNames().get(i);
						eo.setAttribute(param, row[i]);
					}
					rowsNumber ++;
					result.add(eo);
				}
				if (debug)
					log.info("Rows number = "+rowsNumber);
				return rowsNumber;
			} catch (SQLException e) {
				handleSQLException(e);
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
			}
		}
		else if (parsedSentence.toLowerCase().startsWith("update") || 
				parsedSentence.toLowerCase().startsWith("delete"))
		{
			QueryHelper qh = new QueryHelper(conn);
			qh.setEnableNullSqlObject(true);
			try {
				return qh.executeUpdate(parsedSentence, parameters.toArray());
			} catch (SQLException e) {
				handleSQLException(e);
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
			}
		} 
		else if (parsedSentence.toLowerCase().startsWith("{call") )
		{
			try {
				List<Object[]> r = executeCall(conn, null, parameters,
						cursor, parsedSentence);
				int rowsNumber = 0;
				Object [] header = null;
				for (Object[] row: r)
				{
					if (header == null)
						header = row;
					else
					{
						ExtensibleObject eo = new ExtensibleObject();
						eo.setObjectType(obj.getObjectType());
						for (int i = 0; i < row.length; i ++)
						{
							String param = header[i].toString();
							eo.setAttribute(param, row[i]);
						}
						rowsNumber ++;
						for (int i = 0; i < row.length; i ++)
						{
							String param = header[i].toString();
							if (obj.getAttribute(param) == null)
							{
								obj.setAttribute(param, row[i]);
							}
						}
						if (result != null)
							result.add(eo);
					}
				}
				return rowsNumber;
			} catch (SQLException e) {
				handleSQLException(e);
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
			}
		}
		else 
		{
			QueryHelper qh = new QueryHelper(conn);
			qh.setEnableNullSqlObject(true);
			try {
				qh.execute(parsedSentence, parameters.toArray());
				return 1;
			} catch (SQLException e) {
				handleSQLException(e);
				throw new InternalErrorException("Error executing sentence "+parsedSentence, e);
			}
		}

	}

	private List<Object[]> executeCall(Connection conn, Long maxRows,
			List<Object> parameters, Object cursor, String parsedSentence)
			throws SQLException {
		List<Object[]> result = new LinkedList<Object[]>();
		LinkedList<String> columnNames = new LinkedList<String>();
		CallableStatement stmt = conn.prepareCall(parsedSentence);

		try {
			int num = 0;
			int cursorNumber = -1;
			for (Object param : parameters)
			{
				num++;
				if (param == null)
				{
					stmt.setNull(num, Types.VARCHAR);
				}
				else if (param instanceof Long)
				{
					stmt.setLong(num, (Long) param);
				}
				else if (param instanceof Integer)
				{
					stmt.setInt(num, (Integer) param);
				}
				else if (param instanceof Date)
				{
					stmt.setDate(num, (java.sql.Date) param);
				}
				else if (param instanceof java.sql.Timestamp)
				{
					stmt.setTimestamp(num, (java.sql.Timestamp) param);
				}
				else
				{
					stmt.setString(num, param.toString());
				}
			}
			stmt.execute();
			if (cursorNumber >= 0)
			{
				long rows = 0;
				ResultSet rset = (ResultSet) stmt.getObject(cursorNumber);
				try
				{
					int cols = rset.getMetaData().getColumnCount();
					for (int i = 0; i < cols; i++)
					{
						columnNames.add (rset.getMetaData().getColumnLabel(i+1));
					}
					result.add(columnNames.toArray());
					while (rset.next() && (maxRows == null || rows < maxRows.longValue()))
					{
						rows++;
						Object[] row = new Object[cols];
						for (int i = 0; i < cols; i++)
						{
							Object obj = rset.getObject(i + 1);
							if (obj == null)
							{
								int type = rset.getMetaData().getColumnType(i+1);
								if (type == Types.BINARY ||
									type == Types.LONGVARBINARY ||
									type == Types.VARBINARY || type == Types.BLOB ||
									type == Types.DATE || type == Types.TIMESTAMP ||
									type == Types.TIME || type == Types.BLOB)
										row [i] = new NullSqlObjet(type);
							}
							else if (obj instanceof Date)
							{
								row[i] = rset.getTimestamp(i+1);
							}
							else if (obj instanceof BigDecimal)
							{
								row[i] = rset.getLong(i+1);
							}
							else
								row[i] = obj;
						}
						result.add(row);
					}
				}
				finally
				{
					rset.close();
				}
			}
		}
		finally
		{
			stmt.close();
		}
		return result;
	}

	
	private void parseSentence(String sentence, ExtensibleObject obj,
			StringBuffer parsedSentence, List<Object> parameters, Object outputCursor) {
		int position = 0;
		// First, transforma sentence into a valid SQL API sentence
		do
		{
			int nextQuote = sentence.indexOf('\'', position);
			int next = sentence.indexOf(':', position);
			if (next < 0)
			{
				parsedSentence.append (sentence.substring(position));
				position = sentence.length();
			}
			else if (nextQuote >= 0 && next > nextQuote)
			{
				parsedSentence.append (sentence.substring(position, nextQuote+1));
				position = nextQuote + 1;
			}
			else
			{
				parsedSentence.append (sentence.substring(position, next));
				int paramStart = next + 1;
				int paramEnd = paramStart;
				while (paramEnd < sentence.length() && 
						Character.isJavaIdentifierPart(sentence.charAt(paramEnd)))
				{
					paramEnd ++;
				}
				if (paramEnd == paramStart) // A := is being used
					parsedSentence.append (":");
				else
				{
					parsedSentence.append ("?");
					String param = sentence.substring(paramStart, paramEnd);
					Object paramValue =  obj.getAttribute(param);
					if (paramValue == null && param.toLowerCase().startsWith("return"))
						parameters.add(outputCursor);
					else
						parameters.add(paramValue);
				}
				position = paramEnd;
			}
		} while (position < sentence.length());
	}


}
