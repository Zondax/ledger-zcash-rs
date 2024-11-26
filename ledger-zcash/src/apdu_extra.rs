/*******************************************************************************
*   (c) 2022-2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

use ledger_transport::{APDUAnswer, APDUCommand, APDUErrorCode, Exchange};
use ledger_zondax_generic::{ChunkPayloadType, LedgerAppError};

use crate::app::ZcashApp;

impl<E> ZcashApp<E>
where
    E: Exchange,
    E::Error: std::error::Error,
{
    /// Handles the error response from APDU exchange.
    ///
    /// # Arguments
    /// * `response` - The response from the APDU exchange.
    ///
    /// # Returns
    /// A result indicating success or containing a specific ledger application error.
    fn handle_response_error(response: &APDUAnswer<E::AnswerType>) -> Result<(), LedgerAppError<E::Error>> {
        match response.error_code() {
            Ok(APDUErrorCode::NoError) => Ok(()),
            Ok(err) => Err(LedgerAppError::AppSpecific(err as _, err.description())),
            Err(err) => Err(LedgerAppError::Unknown(err)),
        }
    }

    /// Sends chunks of a message with P2 set on all messages.
    /// This is a variant of the `send_chunks` method which specifically sets P2 for all chunks.
    ///
    /// # Arguments
    /// * `transport` - The transport layer used for communication.
    /// * `command` - The initial APDU command.
    /// * `message` - The message to be sent in chunks.
    ///
    /// # Returns
    /// A result containing the final APDU answer or a ledger application error.
    pub(crate) async fn send_chunks_p2_all<I: std::ops::Deref<Target = [u8]> + Send + Sync>(
        transport: &E,
        command: APDUCommand<I>,
        message: &[u8],
    ) -> Result<APDUAnswer<E::AnswerType>, LedgerAppError<E::Error>> {
        const USER_MESSAGE_CHUNK_SIZE: usize = 250;

        let chunks = message.chunks(USER_MESSAGE_CHUNK_SIZE);
        match chunks.len() {
            0 => return Err(LedgerAppError::InvalidEmptyMessage),
            n if n > 255 => return Err(LedgerAppError::InvalidMessageSize),
            _ => (),
        }

        if command.p1 != ChunkPayloadType::Init as u8 {
            return Err(LedgerAppError::InvalidChunkPayloadType);
        }

        let p2 = command.p2;

        // Initial exchange with the transport layer
        let mut response = transport.exchange(&command).await?;
        Self::handle_response_error(&response)?;

        // Send message chunks
        let last_chunk_index = chunks.len() - 1;
        for (packet_idx, chunk) in chunks.enumerate() {
            let mut p1 = ChunkPayloadType::Add as u8;
            if packet_idx == last_chunk_index {
                p1 = ChunkPayloadType::Last as u8
            }

            let command = APDUCommand { cla: command.cla, ins: command.ins, p1, p2, data: chunk.to_vec() };

            response = transport.exchange(&command).await?;
            Self::handle_response_error(&response)?;
        }

        Ok(response)
    }
}
