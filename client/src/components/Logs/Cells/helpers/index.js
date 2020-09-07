import { BLOCK_ACTIONS, DISALLOWED_STATE } from '../../../../helpers/constants';

export const BUTTON_PREFIX = 'btn_';

// TODO: block when NOT_IN_ALLOWED_LIST
export const getBlockClientInfo = (client, disallowed) => {
    const isAllowed = disallowed === DISALLOWED_STATE.ALLOWED_IP;
    const type = isAllowed ? BLOCK_ACTIONS.BLOCK : BLOCK_ACTIONS.UNBLOCK;

    const confirmMessage = isAllowed ? 'client_confirm_block' : 'client_confirm_unblock';
    const buttonKey = isAllowed ? 'disallow_this_client' : 'allow_this_client';
    return {
        confirmMessage,
        buttonKey,
        type,
    };
};
