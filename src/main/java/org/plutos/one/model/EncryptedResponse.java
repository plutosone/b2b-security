package org.plutos.one.model;

import java.util.List;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
// public class EncryptedResponse {
//     private String payload;
//     private Signature signature;
// }
public class EncryptedResponse {

    private String payload;

    private List<Signature> signatures;

    // getters & setters
}

