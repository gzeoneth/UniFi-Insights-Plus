export function identityDescription(source) {
  return {
    wan_configuration: 'Gateway name from current WAN configuration',
    gateway_configuration: 'Gateway address from network configuration',
    vpn_network: 'Label inferred from VPN network',
  }[source] || 'Inventory or saved log name; endpoint identity has not been independently verified'
}

export const PORT_SERVICE_DESCRIPTION = 'IANA registration for this port and protocol; it does not identify the actual application'
