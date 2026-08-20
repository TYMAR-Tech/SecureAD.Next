namespace SecureAD.Kernel.Security;

/// <summary>
/// ACE type values from the Windows security descriptor binary format.
/// Only the types relevant to AD DACL/SACL processing are included.
/// Values match the ACCESS_ALLOWED_ACE_TYPE etc. constants from the Win32 spec.
/// </summary>
public enum AceType : byte
{
    /// <summary>ACCESS_ALLOWED_ACE_TYPE (0x00).</summary>
    AccessAllowed = 0x00,

    /// <summary>ACCESS_DENIED_ACE_TYPE (0x01).</summary>
    AccessDenied = 0x01,

    /// <summary>SYSTEM_AUDIT_ACE_TYPE (0x02).</summary>
    SystemAudit = 0x02,

    /// <summary>ACCESS_ALLOWED_OBJECT_ACE_TYPE (0x05).</summary>
    AccessAllowedObject = 0x05,

    /// <summary>ACCESS_DENIED_OBJECT_ACE_TYPE (0x06).</summary>
    AccessDeniedObject = 0x06,

    /// <summary>SYSTEM_AUDIT_OBJECT_ACE_TYPE (0x07).</summary>
    SystemAuditObject = 0x07,

    /// <summary>ACCESS_ALLOWED_CALLBACK_ACE_TYPE (0x09).</summary>
    AccessAllowedCallback = 0x09,

    /// <summary>ACCESS_DENIED_CALLBACK_ACE_TYPE (0x0A).</summary>
    AccessDeniedCallback = 0x0A,

    /// <summary>ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE (0x0B).</summary>
    AccessAllowedCallbackObject = 0x0B,

    /// <summary>ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE (0x0C).</summary>
    AccessDeniedCallbackObject = 0x0C
}
