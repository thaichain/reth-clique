//! Role-based [access control] for TIP-20 tokens.
//!
//! Implements `AccessControl`: each role has an admin role that can grant/revoke it.
//! [`DEFAULT_ADMIN_ROLE`] is the root admin; [`UNGRANTABLE_ROLE`] is self-administered
//! and cannot be granted externally.
//!
//! [Access control]: <https://docs.tempo.xyz/protocol/tip20/overview#role-based-access-control-rbac>

use alloy::primitives::{Address, B256};

use crate::{
    error::Result,
    storage::Handler,
    tip20::{IRolesAuth, RolesAuthError, RolesAuthEvent, TIP20Token},
};

/// The default admin role (zero hash). Holders can grant/revoke any role.
pub const DEFAULT_ADMIN_ROLE: B256 = B256::ZERO;
/// A self-administered role that cannot be granted by any admin.
pub const UNGRANTABLE_ROLE: B256 = B256::new([0xff; 32]);

impl TIP20Token {
    /// Initializes the roles precompile by setting [`UNGRANTABLE_ROLE`] to be self-administered.
    pub fn initialize_roles(&mut self) -> Result<()> {
        self.set_role_admin_internal(UNGRANTABLE_ROLE, UNGRANTABLE_ROLE)
    }

    /// Grants `DEFAULT_ADMIN_ROLE` to `admin`. Used during token initialization.
    pub fn grant_default_admin(&mut self, msg_sender: Address, admin: Address) -> Result<()> {
        self.grant_role_internal(admin, DEFAULT_ADMIN_ROLE)?;

        self.emit_event(RolesAuthEvent::role_membership_updated(
            DEFAULT_ADMIN_ROLE,
            admin,
            msg_sender,
            true,
        ))
    }

    /// Returns whether `account` holds the given `role`.
    pub fn has_role(&self, call: IRolesAuth::hasRoleCall) -> Result<bool> {
        self.has_role_internal(call.account, call.role)
    }

    /// Returns the admin role that governs `role`.
    pub fn get_role_admin(&self, call: IRolesAuth::getRoleAdminCall) -> Result<B256> {
        self.get_role_admin_internal(call.role)
    }

    /// Grants `role` to `account`.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold the admin role for `role`
    pub fn grant_role(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::grantRoleCall,
    ) -> Result<()> {
        let admin_role = self.get_role_admin_internal(call.role)?;
        self.check_role_internal(msg_sender, admin_role)?;
        self.grant_role_internal(call.account, call.role)?;

        self.emit_event(RolesAuthEvent::role_membership_updated(
            call.role,
            call.account,
            msg_sender,
            true,
        ))
    }

    /// Revokes `role` from `account`.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold the admin role for `role`
    pub fn revoke_role(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::revokeRoleCall,
    ) -> Result<()> {
        let admin_role = self.get_role_admin_internal(call.role)?;
        self.check_role_internal(msg_sender, admin_role)?;
        self.revoke_role_internal(call.account, call.role)?;

        self.emit_event(RolesAuthEvent::role_membership_updated(
            call.role,
            call.account,
            msg_sender,
            false,
        ))
    }

    /// Allows the caller to voluntarily give up their own `role`.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold `role`
    pub fn renounce_role(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::renounceRoleCall,
    ) -> Result<()> {
        self.check_role_internal(msg_sender, call.role)?;
        self.revoke_role_internal(msg_sender, call.role)?;

        self.emit_event(RolesAuthEvent::role_membership_updated(
            call.role, msg_sender, msg_sender, false,
        ))
    }

    /// Changes the admin role that governs `role`.
    ///
    /// # Errors
    /// - `Unauthorized` — caller does not hold the current admin role for `role`
    pub fn set_role_admin(
        &mut self,
        msg_sender: Address,
        call: IRolesAuth::setRoleAdminCall,
    ) -> Result<()> {
        let current_admin_role = self.get_role_admin_internal(call.role)?;
        self.check_role_internal(msg_sender, current_admin_role)?;

        self.set_role_admin_internal(call.role, call.adminRole)?;

        self.emit_event(RolesAuthEvent::role_admin_updated(
            call.role,
            call.adminRole,
            msg_sender,
        ))
    }

    /// Reverts if `account` does not hold `role`.
    ///
    /// # Errors
    /// - `Unauthorized` — account does not hold `role`
    pub fn check_role(&self, account: Address, role: B256) -> Result<()> {
        self.check_role_internal(account, role)
    }

    /// Low-level role check without calldata decoding.
    pub fn has_role_internal(&self, account: Address, role: B256) -> Result<bool> {
        self.roles[account][role].read()
    }

    /// Low-level role grant without authorization checks or events.
    pub fn grant_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        self.roles[account][role].write(true)
    }

    fn revoke_role_internal(&mut self, account: Address, role: B256) -> Result<()> {
        self.roles[account][role].write(false)
    }

    /// Returns the admin role for `role`. An unset entry reads as zero, which is `DEFAULT_ADMIN_ROLE`.
    fn get_role_admin_internal(&self, role: B256) -> Result<B256> {
        self.role_admins[role].read()
    }

    fn set_role_admin_internal(&mut self, role: B256, admin_role: B256) -> Result<()> {
        self.role_admins[role].write(admin_role)
    }

    fn check_role_internal(&self, account: Address, role: B256) -> Result<()> {
        if !self.has_role_internal(account, role)? {
            return Err(RolesAuthError::unauthorized().into());
        }
        Ok(())
    }
}


